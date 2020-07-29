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
#include "variable.hpp"
#include "../trace/tracer.hpp"
#include "../routine/call_convention.hpp"

namespace vtil::symbolic
{
	// Returns the origin block of the pointer.
	//
	static const basic_block* get_pointer_origin( const expression& exp )
	{
		// If variable with valid iterator, return the block.
		//
		if ( exp.is_variable() )
		{
			auto& var = exp.uid.get<variable>();
			if ( var.at.is_valid() )
				return var.at.block;
		}

		// Otherwise try each child.
		//
		for ( auto& exp : { exp.lhs, exp.rhs } )
			if ( auto p = exp ? get_pointer_origin( *exp ) : nullptr )
				return p;

		// Fail.
		//
		return nullptr;
	}

	// Calculates the displacement between two pointers and fills the access_details accordingly.
	//
	static void fill_displacement( access_details* details, const pointer& p1, const pointer& p2, tracer* tracer, bool xblock )
	{
		// If the two pointers can overlap:
		//
		if ( p1.can_overlap( p2 ) )
		{
			// Write dummy bit count and try to calculate the offset:
			//
			details->bit_count = -1;

			// If offset is constant:
			//
			if ( auto disp = p1 - p2 )
			{
				details->bit_offset = math::narrow_cast<bitcnt_t>( *disp * 8 );
				return;
			}
			
			// If valid tracer provided:
			//
			if ( tracer )
			{
				// If two pointers' origins mismatch, propagate first.
				//
				auto o1 = get_pointer_origin( *p1.base );
				auto o2 = get_pointer_origin( *p2.base );
				if ( o1 != o2 && o1 && o2 )
				{
					// Allocate temporary storage for new pointers.
					//
					pointer pn1, pn2;
					std::array in = { &p1, &p2 };
					std::array out = { &pn1, &pn2 };

					// For each pointer:
					//
					for ( auto [in, out] : zip( in, out ) )
					{
						// Transform base pointer:
						//
						expression::reference base = std::move( in->base );
						base.transform( [ & ] ( expression::delegate& exp )
						{
							// Skip if not variable.
							//
							if ( !exp->is_variable() )
								return;
							variable var = exp->uid.get<variable>();

							// Skip if it has an invalid iterator.
							//
							if ( !var.at.is_valid() )
								return;

							// Determine all paths and path restrict the iterator.
							//
							auto& pathset_1 = o1->owner->get_path_bwd( var.at.block, o1 );
							auto& pathset_2 = o1->owner->get_path_bwd( var.at.block, o2 );
							var.at.is_path_restricted = true;

							// If only one of the paths are valid for backwards iteration:
							//
							if ( pathset_1.empty() ^ pathset_2.empty() )
							{
								// Set the restriction.
								//
								var.at.paths_allowed = pathset_1.empty() ? &pathset_2 : &pathset_1;
								exp = tracer->rtrace( std::move( var ) );
							}
							// If both paths are valid for backwards iteration:
							//
							else if ( pathset_1.size() && pathset_2.size() )
							{
								// Calculate for both and set if equivalent.
								//
								var.at.paths_allowed = &pathset_1;
								auto exp1 = tracer->rtrace( var );
								var.at.paths_allowed = &pathset_2;
								auto exp2 = tracer->rtrace( var );
								if ( exp1.equals( *exp2 ) )
									exp = exp1;
							}
						} );

						// Write the new pointer.
						//
						*out = pointer{ std::move( base ) };
					}

					// Recurse with the new pointers.
					//
					return fill_displacement( details, pn1, pn2, nullptr, xblock );
				}
			}

			// If pointer does not strictly overlap and cross-block and tracer 
			// is given, try again after cross-tracing.
			//
			if ( xblock && tracer && !p1.can_overlap_s( p2 ) )
			{
				pointer p1r = { tracer->rtrace_exp( p1.base ) };
				pointer p2r = { tracer->rtrace_exp( p2.base ) };
				return fill_displacement( details, p1r, p2r, nullptr, false );
			}
			// If all fails, declare unknown.
			//
			else
			{
				details->unknown = 1;
			}
		}
		// Otherwise declare no-overlap.
		//
		else
		{
			details->bit_count = 0;
			details->bit_offset = 0;
		}
	}

	// Implement generic access check for ::read_by & ::written_by, write and read must not be both set to true.
	//
	static access_details test_access( const variable& var, const il_const_iterator& it, tracer* tracer, bool write, bool read, bool xblock )
	{
		fassert( !( write && read ) );

		// If variable is of register type:
		//
		if ( auto reg = std::get_if<variable::register_t>( &var.descriptor ) )
		{
			// Iterate each operand:
			//
			for ( int i = 0; i < it->base->operand_count(); i++ )
			{
				// Skip if not register.
				//
				if ( !it->operands[ i ].is_register() )
					continue;

				// Skip if access type does not match.
				//
				if ( write && it->base->operand_types[ i ] < operand_type::write )
					continue;
				if ( read && it->base->operand_types[ i ] == operand_type::write )
					continue;

				// Skip if no overlap.
				//
				auto& ref_reg = it->operands[ i ].reg();
				if ( !ref_reg.overlaps( *reg ) )
					continue;

				// Return access details.
				//
				return {
					.bit_offset = ref_reg.bit_offset - reg->bit_offset,
					.bit_count = ref_reg.bit_count,
					.read = it->base->operand_types[ i ] != operand_type::write,
					.write = it->base->operand_types[ i ] >= operand_type::write
				};
			}
		}
		// If variable is of memory type:
		//
		else if ( auto mem = std::get_if<variable::memory_t>( &var.descriptor ) )
		{
			// If instruction accesses memory:
			//
			if ( it->base->accesses_memory() && 
				 ( !write || it->base->memory_write ) &&
				 ( !read || !it->base->memory_write ) )
			{
				// Generate an expression for the pointer.
				//
				auto [base, offset] = it->memory_location();
				pointer ptr = { tracer->trace( { it, base } ) + offset };

				// Calculate displacement.
				//
				access_details details;
				fill_displacement( &details, ptr, mem->base, tracer, xblock );

				// If pointers can indeed overlap:
				//
				if ( details )
				{
					// Fill read/write.
					//
					details.read = it->base->reads_memory();
					details.write = it->base->writes_memory();

					// If offset is unknown, return as is.
					//
					if ( details.is_unknown() )
						return details;

					// Check if within boundaries, set bit count and return if so.
					//
					bitcnt_t low_offset = details.bit_offset;
					bitcnt_t high_offset = low_offset + it->access_size();
					if ( low_offset < mem->bit_count && high_offset > 0 )
					{
						details.bit_count = it->access_size();
						return details;
					}
				}
			}
		}

		// If external call:
		//
		if ( it->base->is_branching_real() )
		{
			// Get calling convention.
			//
			call_convention cc = it.block->owner->get_cconv( it->vip );

			// If variable is a register:
			//
			if ( var.is_register() )
			{
				auto& reg = var.reg();

				// If $sp, indicate read from:
				//
				if ( reg.is_stack_pointer() )
				{
					if ( write ) return {};
					return {
							.bit_offset = 0,
							.bit_count = reg.bit_count,
							.read = true,
							.write = false
					};
				}

				// If exiting the virtual machine:
				//
				if ( it->base == &ins::vexit )
				{
					// If retval register, indicate read from:
					//
					for ( const register_desc& retval : it.block->owner->routine_convention.retval_registers )
					{
						if ( retval.overlaps( reg ) )
						{
							if ( write ) return {};
							return {
								.bit_offset = retval.bit_offset - reg.bit_offset,
								.bit_count = retval.bit_count,
								.read = true, 
								.write = false
							};
						}
					}

					// If volatile register, indicate discarded:
					//
					for ( const register_desc& retval : it.block->owner->routine_convention.volatile_registers )
					{
						if ( retval.overlaps( reg ) )
						{
							if ( read ) return {};
							return { .bit_offset = 0, .bit_count = reg.bit_count, .read = false, .write = true };
						}
					}

					// If virtual register, indicate discarded:
					//
					if ( reg.is_virtual() )
					{
						if ( read ) return {};
						return { .bit_offset = 0, .bit_count = reg.bit_count, .read = false, .write = true };
					}

					// Otherwise indicate read from.
					//
					if ( write ) return {};
					return {
						.bit_offset = 0,
						.bit_count = reg.bit_count,
						.read = true,
						.write = false
					};
				}

				// If not only looking for read access, check if register is written to.
				//
				access_details wdetails = {};
				if ( !read )
				{
					for ( const register_desc& param : cc.volatile_registers )
					{
						if ( param.overlaps( reg ) )
						{
							wdetails.bit_offset = param.bit_offset - reg.bit_offset;
							wdetails.bit_count = param.bit_count;
							wdetails.write = true;
							break;
						}
					}
					for ( const register_desc& retval : cc.retval_registers )
					{
						if ( retval.overlaps( reg ) )
						{
							wdetails.bit_offset = retval.bit_offset - reg.bit_offset;
							wdetails.bit_count = retval.bit_count;
							wdetails.write = true;
							break;
						}
					}
				}

				// If not only looking for write access, check if register is read from.
				//
				access_details rdetails = {};
				if ( !write )
				{
					for ( const register_desc& param : cc.param_registers )
					{
						if ( param.overlaps( reg ) )
						{
							rdetails.bit_offset = param.bit_offset - reg.bit_offset;
							rdetails.bit_count = param.bit_count;
							rdetails.read = true;
							break;
						}
					}
				}

				// Merge rdetails and wdetails, return.
				//
				if ( !wdetails ) return rdetails;
				if ( !rdetails ) return wdetails;
				return {
					.bit_offset = std::min( wdetails.bit_offset, rdetails.bit_offset ),
					.bit_count = std::max( wdetails.bit_count, rdetails.bit_count ),
					.read = true,
					.write = true
				};
			}
			// If variable is memory:
			//
			else
			{
				auto& mem = var.mem();

				// If vmexit, declared trashed if below or at the shadow space:
				//
				if ( it->base == &ins::vexit ? it.block->owner->routine_convention.purge_stack : cc.purge_stack )
				{
					// Determine the limit of the stack memory owned by this routine.
					//
					expression limit = 
						tracer->trace( { it, REG_SP } ) + 
						it.block->sp_offset + 
						cc.shadow_space;

					// Calculate the displacement, if constant below 0, declare trashed.
					//
					access_details details;
					fill_displacement( &details, mem.base, pointer{ std::move( limit ) }, tracer, xblock );
					if ( !details.is_unknown() && ( details.bit_offset + var.bit_count() ) <= 0 )
					{
						if ( read ) return {};
						return { .bit_offset = 0, .bit_count = var.bit_count(), .read = false, .write = true };
					}
				}

				// Report unknown access: (TODO: Proper parsing!)
				// - We can estimate usage based on registers passed, maybe?
				//
				return { .bit_count = var.bit_count(), .read = true, .write = true, .unknown = true, };
			}
		}

		// No access case.
		//
		return {};
	}

	// Constructs by iterator and the variable descriptor itself.
	//
	variable::variable( const il_const_iterator& it, descriptor_t desc ) :
		descriptor( std::move( desc ) )
	{
		// If read-only register, remove the iterator.
		//
		if ( is_register() && reg().is_read_only() ) bind( {} );
		else                                         bind( it );

		// Validate the variable.
		//
		is_valid( true );
	}
	
	// Construct free-form with only the descriptor itself.
	//
	variable::variable( descriptor_t desc ) 
		: variable( free_form_iterator, std::move( desc ) ) {}

	// Returns whether the variable is valid or not.
	//
	bool variable::is_valid( bool force ) const
	{
		// If register:
		//
		if ( auto* reg = std::get_if<register_t>( &descriptor ) )
		{
			// Iterator must be valid if not read-only.
			//
			cvalidate( at.is_valid() || reg->is_read_only() );

			// Redirect to register descriptor validation.
			//
			return reg->is_valid( force );
		}
		// If memory:
		//
		else
		{
			auto& mem = std::get<memory_t>( descriptor );

			// Iterator must be valid.
			//
			cvalidate( at.is_valid() );

			// Must have a valid pointer of 64 bits.
			//
			cvalidate( mem.decay() && mem.decay().size() == 64 );

			// Bit count should be within (0, 64] and byte-addressable.
			//
			cvalidate( 0 < mem.bit_count && mem.bit_count <= 64 && ( mem.bit_count & 7 ) == 0 );

			return true;
		}
	}

	// Returns whether it is bound to a free-form iterator or not.
	//
	bool variable::is_free_form() const 
	{ 
		return at == free_form_iterator; 
	}

	// Conversion to symbolic expression.
	//
	expression variable::to_expression( bool unpack ) const
	{
		// If memory, return as is.
		//
		if ( is_memory() )
			return { *this, mem().bit_count };

		// If not register (so invalid), return null.
		//
		if ( !is_register() )
			return {};

		// If no unpacking requested, return as is.
		//
		const register_desc& src = reg();
		if ( !unpack )
			return { *this, src.bit_count };

		// Extend to 64-bits with offset set at 0, shift it and
		// mask it to experss the value of original register.
		//
		expression tmp = variable{ at, register_desc{ src.flags, src.local_id, 64, 0, src.architecture } }.to_expression( false );
		if ( src.bit_offset ) tmp >>= src.bit_offset;
		tmp.resize( src.bit_count );
		return tmp;
	}

	// Conversion to human-readable format.
	//
	std::string variable::to_string() const
	{
		// If invalid, return null.
		//
		if ( !is_valid() )
			return "null";

		// Allocate temporary storage for the base name.
		//
		std::string base;

		// If memory:
		//
		if ( auto* mem = std::get_if<memory_t>( &descriptor ) )
		{
			// Indicate dereferencing of the pointer expression.
			//
			base = format::str( "[%s]", mem->decay() );

			// Prefix with read size:
			//
			switch ( mem->bit_count )
			{
				case 1*8:  base = "byte"  + base; break;
				case 2*8:  base = "word"  + base; break;
				case 4*8:  base = "dword" + base; break;
				case 6*8:  base = "fword" + base; break;
				case 8*8:  base = "qword" + base; break;
				default:   base = "u" + std::to_string( mem->bit_count ) + base; break;
			}
		}
		// If register:
		//
		else
		{
			// Redirect to register_desc string conversion.
			//
			base = std::get<register_t>( descriptor ).to_string();
		}

		// Indicate branch-dependence.
		//
		if ( is_branch_dependant )
			base += "...";

		// If no valid iterator, return as is.
		//
		if ( !at.is_valid() )
			return base;

		// If dummy iterator, return with free-indicator appended.
		//
		if ( at == free_form_iterator )
			return "%" + base;

		// Append the block identifier.
		//
		base = format::str( "%s#0x%llx", base, at.block->entry_vip );

		// Append the stream index and return.
		//
		if ( at.is_begin() )    return base + "?";
		else if ( at.is_end() ) return base + "*";
		else                    return base + "." + std::to_string( std::distance( at.block->begin(), at ) );
	}

	// Packs all the variables in the expression where it'd be optimal.
	//
	expression::reference& variable::pack_all( expression::reference& exp )
	{
		// List of ideal packers.
		//
		static constexpr bitcnt_t ideal_packers[] = { 1, 8, 16, 32 };
		return exp.transform( [ ] ( expression::delegate& exp )
		{
			// Skip if expression has any known 1s.
			//
			if ( exp->known_one() )
				return;

			// Skip if expression does not have exactly one variable.
			//
			if ( exp->count_unique_variables() != 1 )
				return;

			// Check if the unknown mask matches that of an ideal packer.
			//
			auto it = std::find_if( ideal_packers, std::end( ideal_packers ), [ & ] ( auto& n )
			{
				return math::fill( n ) == exp->unknown_mask();
			} );
			if ( it == std::end( ideal_packers ) )
				return;

			// For each ideal packer:
			//
			bitcnt_t bitsize = *it;

			// Clone and resize the expression.
			//
			auto exp_resized = expression::reference{ exp.ref }.resize( bitsize );

			// If top node is not __ucast, fail.
			//
			if ( exp_resized->op != math::operator_id::ucast )
				return;

			// If node is not shift right, use zero offset.
			//
			bitcnt_t offset;
			auto node = exp_resized->lhs;
			if ( node->op != math::operator_id::shift_right )
			{
				offset = 0;
			}
			// If rhs is constant, use as is for offset.
			//
			else if ( auto n = node->rhs->get<bitcnt_t>() )
			{
				offset = *n;
				node = node->lhs;
			}
			// Otherwise, fail.
			//
			else
			{
				return;
			}

			// Fail if top node is not a variable.
			//
			if ( !node->is_variable() )
				return;

			// Fail if the variable is not a register.
			//
			const variable& var = node->uid.get<variable>();
			if ( !var.is_register() )
				return;

			// Fail if cannot be fit.
			//
			const register_desc& reg = var.reg();
			if ( reg.bit_count < bitsize )
				return;

			// Fail if final bit offset is not aligned.
			//
			if ( ( reg.bit_offset + offset ) % bitsize )
				return;

			// Deref top-level node, own current node, rewrite as the variable.
			//
			exp_resized.reset();
			auto exp_node = node.own();
			variable& var_new = exp_node->uid.get<variable>();
			var_new.reg().bit_count = bitsize;
			var_new.reg().bit_offset += offset;
			exp_node->value = math::bit_vector( bitsize );
			exp_node->update( false );
			exp = node.resize( exp->size() );
		} );
	}
	expression::reference variable::pack_all( const expression::reference& exp )
	{
		auto copy = make_copy( exp );
		pack_all( copy );
		return copy;
	}

	// Checks if the variable is read by / written by the given instruction, 
	// returns nullopt it could not be known at compile-time, otherwise the
	// access details as described by access_details. Tracer is used for
	// pointer resolving, if nullptr passed will use default tracer.
	//
	access_details variable::read_by( const il_const_iterator& it, tracer* tr, bool xblock ) const
	{
		return test_access( *this, it, tr ? tr->purify() : nullptr, false, true, xblock );
	}
	access_details variable::written_by( const il_const_iterator& it, tracer* tr, bool xblock ) const
	{
		return test_access( *this, it, tr ? tr->purify() : nullptr, true, false, xblock );
	}
	access_details variable::accessed_by( const il_const_iterator& it, tracer* tr, bool xblock ) const
	{
		return test_access( *this, it, tr ? tr->purify() : nullptr, false, false, xblock );
	}
};