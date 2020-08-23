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
// 3. Neither the name of VTIL Project nor the names of its contributors
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.   
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
				result |= is_local( *var.mem().decay() );
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
			lookup.at.restrict_path( var.at.block, false );
			return rec ? tracer->rtrace_p( std::move( lookup ) ) : tracer->trace_p( std::move( lookup ) );
		};

		// If at the end of improperly terminated block, declare used.
		//
		constexpr auto is_improper_end = [ ] ( const il_const_iterator& it ) 
		{
			return std::next( it ).is_end() && it.block->next.empty() && it->base != &ins::vexit;
		};
		if( is_improper_end( var.at ) )
			return true;

		// If memory variable:
		//
		if ( var.is_memory() )
		{
			// If it can't be simplified into $sp + C, assume used.
			//
			std::optional delta_o = var.mem().decay()->evaluate( [ ] ( const symbolic::unique_identifier& uid )
																-> std::optional<uint64_t>
			{
				auto var = uid.get<symbolic::variable>();
				if ( var.is_register() && var.reg().is_stack_pointer() )
					return 0ull;
				return std::nullopt;
			} ).get<true>();
			if ( !delta_o ) return true;
			// TODO: Trace pointer.
		}

		// Declare iteration logic.
		//
		bool is_used = false;
		bool is_nr_dead = false;
		uint64_t mask_0 = math::fill( var.bit_count() );
		auto enumerator = [ &, mask = mask_0, skip_count = 0, local_var = var ]( const il_const_iterator& it ) mutable
		{
			const auto declare_used = [ & ] ()
			{
				is_used = true;
				return enumerator::obreak_r;
			};

			// Skip first instruction.
			//
			if ( skip_count++ == 0 )
				return enumerator::ocontinue;
			
			// If memory variable:
			//
			if ( var.is_memory() )
			{
				// Propagate pointer if needed.
				//
				if ( local_var.at.block != it.block )
				{
					if ( local_var.at.block->sp_index == 0 )
					{
						symbolic::expression exp =
							local_var.mem().decay()
							- local_var.at.block->sp_offset
							+ symbolic::variable{ it.block->begin(), REG_SP }.to_expression()
							- symbolic::variable{ local_var.at.block->begin(), REG_SP }.to_expression();
						local_var = symbolic::variable{ it.block->begin(), { symbolic::pointer{ exp }, local_var.mem().bit_count } };
					}
				}

				// If instruction is branching, check if stack is discarded.
				//
				if ( it->base->is_branching() && it.block->owner->routine_convention.purge_stack )
				{
					// Assert this instruction does not read memory.
					//
					fassert( !it->base->reads_memory() );

					// Determine the displacement between high write and discarded limit.
					//
					symbolic::expression write_high = local_var.mem().decay() + ( local_var.mem().bit_count / 8 );
					symbolic::expression discard_limit = rel_ptr( { it, REG_SP } ) + it->sp_offset;
					std::optional disp = ( write_high - discard_limit ).get<true>();

					// If displacement is an immediate value and is below 0, declare discarded.
					//
					if ( disp && *disp <= 0 )
					{
						mask = 0;
						is_nr_dead = true;
						return enumerator::obreak;
					}
					// TODO: Partial discarding??
				}
			}

			// Check if variable is accessed by this instruction.
			//
			if ( auto details = local_var.accessed_by( it, tracer, !is_restricted ) )
			{
				// If possible read, declare used.
				//
				if ( details.read )
				{
					if ( details.is_unknown() || ( mask & math::fill( details.bit_count, details.bit_offset ) ) )
						return declare_used();
				}
				// If known overwrite:
				//
				else if ( details.write && !details.is_unknown() )
				{
					// Clear the mask.
					//
					mask &= ~math::fill( details.bit_count, details.bit_offset );
				}
			}

			// Break if value is dead.
			//
			if ( !mask )
			{
				is_nr_dead = true;
				return enumerator::obreak;
			}

			// If improperly terminated block, declare used, else skip.
			//
			return is_improper_end( it ) ? declare_used() : enumerator::ocontinue;
		};

		// Invoke the enumerator.
		//
		auto it = var.at;
		if ( is_restricted ) it.restrict_path();
		var.at.block->owner->enumerate(
			enumerator,
			it
		);

		// If found an instruction reading the value, indicate so.
		//
		if ( is_used ) 
			return true;

		// If query was not restricted or if mask is dead, declare not-used.
		//
		if ( !is_restricted || is_nr_dead ) 
			return false;

		// Report used if global register and block is not exiting vm.
		//
		return ( !var.at.block->is_complete() || var.at.block->back().base != &ins::vexit ) && 
			   ( !var.is_register() || var.reg().is_global() );
	}

	// Helper to check if the given symbolic variable's value is preserved upto [dst].
	//
	bool is_alive( const symbolic::variable& var, const il_const_iterator& dst, bool rec, tracer* tracer )
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
			if ( var.reg().is_local() && var.at.block != dst.block )
				return false;
		}

		// Create enumerator and return is_alive after execution.
		//
		bool is_alive = true;
		auto check = [ & ] ( const il_const_iterator& it )
		{
			// If instruction writes to the variable:
			//
			if ( var.written_by( it, tracer, rec ) )
			{
				// Mark dead and break recursively.
				//
				is_alive = false;
				return enumerator::obreak_r;
			}

			// If not, continue iteration.
			//
			return enumerator::ocontinue;
		};
		dst.block->owner->enumerate( check, var.at, dst );
		return is_alive;
	}

	// Revives the value of the given variable to be used by the point specified.
	//
	register_desc revive_register( const symbolic::variable& var, const il_iterator& it )
	{
		fassert( var.is_register() );

		// Drop const-qualifiers, this operation is not illegal since we're passed 
		// non-constant iterator, meaning we have access to the routine itself.
		//
		basic_block* source = ( basic_block* ) var.at.block;
		il_iterator access_point = source->acquire( var.at );

		// Allocate an appropriate temporary based on local-ness.
		//
		register_desc temporary = it.block != var.at.block
			? source->owner->alloc( var.bit_count() )
			: source->tmp( var.bit_count() );

		// Insert a move-to-temporary before this instruction and swap each read 
		// of the register we revived at the access point with the new temporary.
		//
		for ( auto [op, type] : ( +access_point )->enum_operands() )
			if ( type < operand_type::write && op.is_register() && op.reg() == var.reg() )
				op = temporary;
		source->insert( access_point, { &ins::mov, { temporary, var.reg() } } );
		return temporary;
	}

	// Returns each possible branch destination of the given basic block in the format of:
	// - [is_real, target] x N
	//
	branch_info analyze_branch( const basic_block* blk, tracer* tracer, branch_analysis_flags flags )
	{
		// If block is not complete, return empty vector.
		//
		if ( !blk->is_complete() )
			return {};

		// Declare tracer.
		//
		const auto trace = [ & ] ( symbolic::variable&& lookup )
		{
			symbolic::expression::reference exp = tracer->trace( lookup );
			if ( flags.cross_block ) exp = tracer->rtrace_exp( exp );
			if ( flags.pack )        symbolic::variable::pack_all( exp );
			return exp;
		};

		// Declare operand->expression helper.
		//
		auto branch = std::prev( blk->end() );
		auto discover = [ & ] ( const operand& op_dst, bool real, bool parse = true ) -> branch_info
		{
			// Determine the symbolic expression describing branch destination.
			//
			symbolic::expression::reference destination = op_dst.is_immediate()
				? symbolic::expression{ op_dst.imm().u64 }
				: trace( { branch, op_dst.reg() } );

			// Remove any matches of REG_IMGBASE and pack.
			//
			destination.transform( [ ] ( symbolic::expression::delegate& ex )
			{
				if ( ex->is_variable() )
				{
					auto& var = ex->uid.get<symbolic::variable>();
					if ( var.is_register() && var.reg() == REG_IMGBASE )
						*+ex = { 0, ex->size() };
				}
			}, true, false ).simplify( true );

			// If parsing requested:
			//
			if ( parse )
			{
				// Match classic Jcc:
				//
				const auto extract_and_transform_cnd = [ & ] ( symbolic::expression::reference& dst, symbolic::expression::reference& cnd_out, bool state )
				{
					bool confirmed = false;

					const std::function<void( const symbolic::expression& )> explore_cc_space = [ & ] ( const symbolic::expression& exp )
					{
						if ( exp.op == math::operator_id::value_if )
						{
							if ( !cnd_out )
								cnd_out = exp.lhs;
						}
						else if ( ( exp.value.unknown_mask() | exp.value.known_one() ) == 1 )
						{
							if ( !cnd_out && !exp.is_constant() )
								cnd_out = exp;
						}
						else if ( exp.is_variable() && exp.uid.get<symbolic::variable>().is_memory() )
						{
							exp.uid.get<symbolic::variable>().mem().decay()->enumerate( explore_cc_space );
						}
					};

					const std::function<void( symbolic::expression::delegate& )> transform_cc = [ & ] ( symbolic::expression::delegate& exp )
					{
						if ( exp->op == math::operator_id::value_if )
						{
							if ( exp->lhs->is_identical( *cnd_out ) )
							{
								exp = state ? exp->rhs : symbolic::expression{ 0 };
								confirmed |= !state;
							}
							else if ( exp->lhs->is_identical( ~cnd_out ) )
							{
								exp = state ? symbolic::expression{ 0 } : exp->rhs;
								confirmed |= !state;
							}
						}
						else if ( ( exp->value.unknown_mask() | exp->value.known_one() ) == 1 )
						{
							if ( exp->is_identical( *cnd_out ) )
							{
								*+exp = symbolic::expression{ state, exp->size() };
								confirmed |= !state;
							}
							else if ( exp->is_identical( ~cnd_out ) )
							{
								*+exp = symbolic::expression{ state ^ 1, exp->size() };
								confirmed |= !state;
							}
						}
						else if ( exp->is_variable() && exp->uid.get<symbolic::variable>().is_memory() )
						{
							auto& var = exp->uid.get<symbolic::variable>();
						
							// Disable cross block tracing while we trace the pointer.
							//
							branch_analysis_flags orig_flags = flags;
							flags.cross_block = false;
							symbolic::pointer exp_ptr = var.mem().decay().transform( transform_cc );
							flags = orig_flags;

							if ( exp_ptr != var.mem().base )
								exp = trace( symbolic::variable{ std::next( var.at ), { exp_ptr, var.mem().bit_count } } );
						}
					};

					dst->enumerate( explore_cc_space );
					if ( cnd_out )    dst.transform( transform_cc );
					if ( !confirmed ) cnd_out = {};
				};

				symbolic::expression::reference cc = {};
				symbolic::expression::reference dst1 = destination;
				symbolic::expression::reference dst2 = destination;
				extract_and_transform_cnd( dst1, cc, true );
				extract_and_transform_cnd( dst2, cc, false );

				if ( cc )
				{
					return {
						.is_vm_exit = real,
						.is_jcc = true,
						.cc = std::move( cc ),
						.destinations = { std::move( dst1 ), std::move( dst2 ) }
					};
				}

				// -- TODO: Handle jump tables.
				//
			}
			
			// Otherwise assume direct jump.
			//
			return {
				.is_vm_exit = real,
				.destinations = { std::move( destination ) }
			};
		};

		// Discover all targets and return.
		//
		if ( branch->base == &ins::jmp )
			return discover( branch->operands[ 0 ], false );
		if ( branch->base == &ins::vexit )
			return discover( branch->operands[ 0 ], true );
		if ( branch->base == &ins::vxcall )
			return discover( branch->operands[ 0 ], true );
		if ( branch->base == &ins::js )
		{
			// If condition can be resolved in compile time:
			//
			auto cc = trace( { branch, branch->operands[ 0 ].reg() } );
			if ( flags.resolve_opaque && cc->is_constant() )
			{
				// Redirect to jmp resolver.
				//
				return discover( branch->operands[ *cc->get<bool>() ? 1 : 2 ], false, false );
			}

			// Resolve each individually and form jcc.
			//
			branch_info b1 = discover( branch->operands[ 1 ], false, false );
			branch_info b2 = discover( branch->operands[ 2 ], false, false );
			return {
				.is_vm_exit = false,
				.is_jcc = true,
				.cc = std::move( cc ),
				.destinations = { std::move( b1.destinations[ 0 ] ), std::move( b2.destinations[ 0 ] ) }
			};
		}
		unreachable();
	}

	// Checks if an instruction is a semantic NOP.
	//
	bool is_semantic_nop( const instruction& ins )
	{
		// MOV to self.
		//
		if ( ins.base == &ins::mov ||
			 ins.base == &ins::movsx )
		{
			if ( ins.operands[ 0 ] == ins.operands[ 1 ] )
				return true;
		}

		// All mathematical operations with identity constants.
		// - TODO: Fix to use global simplifier table.
		//
		auto is_so = [ & ] ( const instruction_desc& insd, std::initializer_list<std::pair<int, uint64_t>> checks )
		{
			if ( ins.base != &insd ) return false;

			for ( auto [index, constant] : checks )
			{
				if ( !ins.operands[ index ].is_immediate() )
					return false;

				if ( math::descriptor_of( insd.symbolic_operator ).is_signed )
					constant = math::sign_extend( constant, ins.access_size() );
				else
					constant = math::zero_extend( constant, ins.access_size() );

				if ( ins.operands[ index ].imm().u64 != constant )
					return false;
			}

			return true;
		};

		return
			is_so( ins::add,  { { 1, 0 }               } ) ||
			is_so( ins::sub,  { { 1, 0 }               } ) ||
			is_so( ins::mul,  { { 1, 1 }               } ) ||
			is_so( ins::imul, { { 1, 1 }               } ) ||
			is_so( ins::div,  { { 1, 0 }, { 2, 1 }     } ) ||
			is_so( ins::idiv, { { 1, 0 }, { 2, 1 }     } ) ||
			is_so( ins::rem,  { { 1, 0 }, { 2, ~0ull } } ) ||
			is_so( ins::bshl, { { 1, 0 }               } ) ||
			is_so( ins::bshr, { { 1, 0 }               } ) ||
			is_so( ins::brol, { { 1, 0 }               } ) ||
			is_so( ins::bror, { { 1, 0 }               } ) ||
			is_so( ins::bxor, { { 1, 0 }               } ) ||
			is_so( ins::bor,  { { 1, 0 }               } ) ||
			is_so( ins::band, { { 1, ~0ull }           } );
	}

	// Removes all NOPs,.
	//
	size_t remove_nops( basic_block* blk, bool semantic_nops, bool volatile_nops )
	{
		size_t n = 0;
		for ( auto it = blk->begin(); !it.is_end(); )
		{
			if ( ( volatile_nops || !it->is_volatile() ) && ( it->base == &ins::nop || ( semantic_nops && is_semantic_nop( *it ) ) ) )
				it = blk->erase( it ), n++;
			else
				it++;
		}
		return n;
	}
	size_t remove_nops( routine* rtn, bool semantic_nops, bool volatile_nops )
	{
		size_t n = 0;
		rtn->for_each( [ & ] ( basic_block* blk ) { n += remove_nops( blk, semantic_nops, volatile_nops ); } );
		return n;
	}
};
