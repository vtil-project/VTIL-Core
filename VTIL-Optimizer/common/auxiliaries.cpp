// Copyright (c) 2020 Can Boluk and contributors of the VTIL Project   
// All rights reserved.   
//    
// Redistribution and use in source and binary forms, with or without   
// modification, are permitted provided that the following conditions are met: 
//    
// 1. Redistributions of source code must retain the above copyright notice,   
//    this list of conditions and the following disclaimer.   
// 2. Redistributions in binary form must reproduce the above copyright   
//    notice, this list of conditions and the following disclaimer in the   
//    documentation and/or other materials provided with the distribution.   
// 3. Neither the name of mosquitto nor the names of its   
//    contributors may be used to endorse or promote products derived from   
//    this software without specific prior written permission.   
//    
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE   
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR   
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF   
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS   
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN   
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)   
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  
// POSSIBILITY OF SUCH DAMAGE.        
//
#include "auxiliaries.hpp"
#include <vtil/query>
#include <vtil/io>
#include <vtil/math>

namespace vtil::optimizer::aux
{
	// Helper to check if the expression given is block-local.
	//
	bool is_local( const symbolic::expression& ex )
	{
		// Allocate temporary result and enumerate each unique identifier
		// by passing lambda as eval lookup helper.
		//
		bool result = false;
		ex.evaluate( [ & ] ( const symbolic::unique_identifier& uid )
		{
			// If variable is register, check if local, else recurse into the pointer.
			//
			auto& var = uid.get<symbolic::variable>();
			if ( var.is_memory() )
				result |= is_local( var.mem().decay() );
			else
				result |= var.reg().is_local();

			// Return dummy result.
			//
			return 0ull;
		} );
		return result;
	}

	// Helper to check if the current value stored in the variable is used by the routine.
	// TODO: Doesnt discard based on block offset!
	//
	bool is_used( const symbolic::variable& var, bool rec, tracer* tracer )
	{
		// Assert variable is properly bound.
		//
		fassert( var.at.is_valid() );

		// Save original recursion restriction.
		//
		bool is_restricted = !rec;

		// Declare a relative pointer tracer.
		//
		auto rel_ptr = [ & ] ( symbolic::variable lookup )
		{
			// Restrict iteration upto origin and forward to rtrace.
			//
			lookup.at.restrict_path( var.at.container, false );
			return tracer->rtrace_p( std::move( lookup ) );
		};

		// Create a dummy query and allocate the variable mask.
		//
		uint64_t variable_mask;
		auto blueprint = query::dummy<il_const_iterator>().unproject();

		// Allocate dummy pointer.
		//
		symbolic::variable ptr_var;

		// If memory variable:
		//
		if ( var.is_memory() )
		{
			ptr_var = var;

			// If it can't be simplified into $sp + C, assume used.
			//
			std::optional delta_o = var.mem().decay().evaluate( [ ] ( const symbolic::unique_identifier& uid )
															-> std::optional<uint64_t>
			{
				auto var = uid.get<symbolic::variable>();
				if ( var.is_register() && var.reg().is_stack_pointer() )
					return 0ull;
				return std::nullopt;
			} ).get<true>();
			if ( !delta_o ) return true;

			// Create a mask for the variable and a path.
			//
			variable_mask = math::fill( var.mem().bit_count );

			// Declare iteration logic.
			//
			blueprint

				// @ Clear from the active mask per overwrite.
				.run( [ & ] ( const il_const_iterator& it ) 
				{
					auto& pvar = query::rlocal( ptr_var );

					// Propagate pointer if needed.
					//
					if ( pvar.at.container != it.container )
					{
						if ( pvar.at.container->sp_index == 0 )
						{
							symbolic::expression exp = pvar.mem().decay();
							exp = 
								exp
								- pvar.at.container->sp_offset 
								+ symbolic::variable{ it.container->begin(), REG_SP }.to_expression()
								- symbolic::variable{ pvar.at.container->begin(), REG_SP }.to_expression();
							pvar = symbolic::variable{ it.container->begin(), { symbolic::pointer{ exp }, pvar.mem().bit_count } };
						}
					}

					// If instruction is branching, check if stack is discarded.
					//
					if ( it->base->is_branching() && it.container->owner->routine_convention.purge_stack )
					{
						// Assert this instruction does not read memory.
						//
						fassert( !it->base->reads_memory() );

						// Determine the displacement between high write and discarded limit.
						//
						symbolic::expression write_high = pvar.mem().decay() + ( pvar.mem().bit_count / 8 );
						symbolic::expression discard_limit = rel_ptr( { it, REG_SP } ) + it->sp_offset;
						std::optional disp = ( write_high - discard_limit ).get<true>();

						// If displacement is an immediate value and is below 0, declare discarded.
						//
						if ( disp && *disp < 0 )
							query::rlocal( variable_mask ) = 0;
					}

					// Skip if variable is not written to by this instruction.
					//
					auto details = pvar.written_by( it, tracer );
					if ( !details ) return;

					// If also read or if unknown access, skip.
					//
					if ( details.is_unknown() || details.read )
						return;

					// Clear the mask.
					//
					query::rlocal( variable_mask ) &= ~math::fill( details.bit_count, details.bit_offset );
				} )

				// | Skip further checks if value is dead.
				.whilst( [ & ] ( const il_const_iterator& it ) { return query::rlocal( variable_mask ) != 0; } )

				// >> Select the instructions that read the value previously written.
				.where( [ & ] ( const il_const_iterator& it )
				{
					auto& pvar = query::rlocal( ptr_var );

					// Skip if variable is not read by this instruction.
					//
					auto details = pvar.read_by( it, tracer );
					if ( !details ) return false;

					// If unknown access, continue.
					//
					if ( details.is_unknown() )
						return true;

					// If an alive part of the value is read, continue.
					//
					if ( query::rlocal( variable_mask ) & math::fill( details.bit_count, details.bit_offset ) )
						return true;

					// If we are exiting the virtual machine:
					//
					if ( it->base->is_branching_real() )
					{
						// Use the symbolic variable API.
						//
						if ( auto details = pvar.accessed_by( it, tracer ) )
						{
							// If unknown, assume used.
							//
							if ( details.is_unknown() )
								return true;

							// If read from, declare used.
							//
							uint64_t adjusted_mask = math::fill( details.bit_count, details.bit_offset );
							if ( details.read && ( adjusted_mask & query::rlocal( variable_mask ) ) )
								return true;

							// If written to, clear mask.
							//
							if ( details.write )
								query::rlocal( variable_mask ) &= ~adjusted_mask;
						}
					}

					return false;
				} );
		}
		// If register variable:
		//
		else
		{
			auto& reg = var.reg();

			// If volatile register, assume used.
			//
			if ( reg.is_volatile() )
				return true;

			// Create a mask for the variable.
			//
			variable_mask = reg.get_mask();

			// If local register, strip recursive flag.
			//
			if ( reg.is_local() )
				rec = false;

			// Declare iteration logic.
			//
			blueprint
				// | Skip further checks if value is dead.
				.whilst( [ & ] ( const il_const_iterator& it ) { return query::rlocal( variable_mask ) != 0; } )

				// @ Clear from the active mask per overwrite.
				.run( [ & ] ( const il_const_iterator& it ) 
				{
					// For each register this instruction overwrites:
					//
					for ( auto [op, type] : it->enum_operands() )
					{
						if ( type != operand_type::write )
							continue;

						// If register overlaps, strip from mask.
						//
						if ( op.reg().overlaps( reg ) )
							query::rlocal( variable_mask ) &= ~op.reg().get_mask();
					}
				} )

				// >> Select the instructions that read the value previously written.
				.where( [ & ] ( const il_const_iterator& it )
				{
					// For each register this instruction reads from:
					//
					for ( auto [op, type] : it->enum_operands() )
					{
						if ( type == operand_type::write || !op.is_register() )
							continue;

						// If register overlaps, and value is alive, pick.
						//
						if ( op.reg().overlaps( reg ) && query::rlocal( variable_mask ) & op.reg().get_mask() )
							return true;
					}

					// If we are exiting the virtual machine:
					//
					if ( it->base->is_branching_real() )
					{
						// Use the symbolic variable API.
						//
						if ( auto details = var.accessed_by( it, tracer ) )
						{
							// If unknown, assume used.
							//
							if ( details.is_unknown() )
								return true;

							// If read from, declare used.
							//
							uint64_t adjusted_mask = math::fill( details.bit_count, details.bit_offset + reg.bit_offset );
							if ( details.read && ( adjusted_mask & query::rlocal( variable_mask ) ) )
								return true;

							// If written to, clear mask.
							//
							if ( details.write )
								query::rlocal( variable_mask ) &= ~adjusted_mask;
						}
					}

					return false;
				} );
		}

		// Start the query depending on the recursiveness and return result.
		//
		if ( rec )
		{
			int skip_count = 0;

			// => Begin forward iterating query:
			auto res = query::create_recursive( var.at, +1 )

				// >> Skip one.
				.where( [ & ] ( auto& ) { return query::rlocal( skip_count )++ >= 1; } )

				// @ Make the current mask local per recursion.
				.bind( variable_mask, ptr_var, skip_count )

				// @ Attach controller.
				.control( blueprint.to_controller() )

				// := Project to iterator form.
				.unproject()

				// <= Return first result and flatten the tree.
				.first().flatten( true );

			// Return used if any instruction reading from this value is hit.
			//
			return !res.result.empty();
		}
		else
		{
			// => Begin forward iterating query:
			auto res = query::create( var.at, +1 )

				// >> Skip one.
				.skip( 1 )

				// @ Attach controller.
				.control( blueprint.to_controller() )

				// := Project to iterator form.
				.unproject()

				// <= Return first result.
				.first();

			// If found an instruction reading the value, indicate so.
			//
			if ( res.has_value() ) 
				return true;

			// If there is a next block and mask is not cleared:
			//
			if ( !var.at.container->next.empty() && variable_mask != 0 )
			{
				// If query was restricted, report used if not local register.
				//
				if ( is_restricted )
					return !var.is_register() || !var.reg().is_local();
			}

			// Report not used.
			//
			return false;
		}
	}

	// Helper to check if the given symbolic variable's value is preserved upto [dst].
	//
	bool is_alive( const symbolic::variable& var, const il_const_iterator& dst, tracer* tracer )
	{
		// If register:
		//
		if ( var.is_register() )
		{
			// If read-only, report alive.
			//
			if ( var.reg().is_read_only() )
				return true;

			// If volatile, report dead.
			//
			if ( var.reg().is_volatile() )
				return false;

			// If local report dead if cross-block.
			//
			if ( var.reg().is_local() && var.at.container != dst.container )
				return false;
		}

		// If block-local check:
		//
		if( var.at.container == dst.container )
		{
			// => Begin a foward iterating query.
			//
			auto res = query::create( var.at, +1 )
				// | Stop execution if the destination is reached.
				.until( dst )
				// := Project back to the iterator type.
				.unproject()
				// >> Skip until we find a write into the variable queried.
				.where( [ & ] ( const il_const_iterator& i ) { return var.written_by( i, tracer ); } )
				// <= Return first match.
				.first();

			// If no match was found, register is alive.
			//
			return !res.has_value();
		}
		// If cross-block check:
		//
		else
		{
			// Restrict iterator.
			//
			auto it_rstr = il_const_iterator{ var.at }
				.clear_restrictions()
				.restrict_path( dst.container, true );

			// => Begin a foward iterating recursive query.
			//
			auto res = query::create_recursive( it_rstr, +1 )
				// | Stop execution if the destination is reached.
				.until( dst )
				// := Project back to the iterator type.
				.unproject()
				// >> Skip until we find a write into the variable queried.
				.where( [ & ] ( const il_const_iterator& i ) { return var.written_by( i, tracer ); } )
				// <= Return first match.
				.first();

			// If no match was found, register is alive.
			//
			return res.flatten( true ).result.empty();
		}
	}

	// Revives the value of the given variable to be used by the point specified.
	//
	register_desc revive_register( const symbolic::variable& var, const il_iterator& it )
	{
		fassert( var.is_register() );

		// If cross block operation, lock routine mutex.
		//
		cnd_unique_lock _g{ it.container->owner->mutex, it.container != var.at.container };

		// Drop const-qualifiers, this operation is not illegal since we're passed 
		// non-constant iterator, meaning we have access to the routine itself.
		//
		basic_block* source = ( basic_block* ) var.at.container;
		il_iterator access_point = source->acquire( var.at );

		// Allocate an appropriate temporary based on local-ness.
		//
		register_desc temporary = it.container != var.at.container
			? source->owner->alloc( var.bit_count() )
			: source->tmp( var.bit_count() );

		// Insert a move-to-temporary before this instruction and swap each read 
		// of the register we revived at the access point with the new temporary.
		//
		for ( auto [op, type] : access_point->enum_operands() )
			if ( type < operand_type::write && op.is_register() && op.reg() == var.reg() )
				op = temporary;
		source->insert( access_point, { &ins::mov, { temporary, var.reg() } } );
		return temporary;
	}

	// Returns each possible branch destination of the given basic block in the format of:
	// - [is_real, target] x N
	//
	std::vector<std::pair<bool, symbolic::expression>> discover_branches( const basic_block* blk, tracer* tracer, bool xblock )
	{
		// If block is not complete, return empty vector.
		//
		std::vector<std::pair<bool, symbolic::expression>> targets = {};
		if ( !blk->is_complete() )
			return targets;

		// Declare operand->expression helper.
		//
		auto branch = std::prev( blk->end() );
		auto discover = [ & ] ( const operand& op_dst, bool real )
		{
			// Determine the symbolic expression describing branch destination.
			//
			symbolic::expression destination = op_dst.is_immediate()
				? symbolic::expression{ op_dst.imm().u64 }
				: ( xblock ? tracer->rtrace_p( { branch, op_dst.reg() } ) : tracer->trace_p( { branch, op_dst.reg() } ) );

			// Remove any matches of REG_IMGBASE and pack.
			//
			destination.transform( [ ] ( symbolic::expression& ex )
			{
				if ( ex.is_variable() )
				{
					auto& var = ex.uid.get<symbolic::variable>();
					if ( var.is_register() && var.reg() == REG_IMGBASE )
						ex = { 0, ex.size() };
				}
			} ).simplify( true );

			// Match classic Jcc:
			//
			using namespace symbolic::directive;
			std::vector<symbol_table_t> results;
			if ( fast_match( &results, U + ( __if( A, C ) + __if( B, D ) ), destination ) )
			{
				auto& sym = results.front();
				if ( sym.translate( A )->equals( ~sym.translate( B ) ) )
				{
					targets.emplace_back( real, sym.translate( U ) + sym.translate( C ) );
					targets.emplace_back( real, sym.translate( U ) + sym.translate( D ) );
					return;
				}
			}

			// If not, push as is.
			//
			targets.emplace_back( real, destination );
		};

		// Discover all targets and return.
		//
		for ( int idx : branch->base->branch_operands_vip )
			discover( branch->operands[ idx ], false );
		for ( int idx : branch->base->branch_operands_rip )
			discover( branch->operands[ idx ], true );
		return targets;
	}
};
