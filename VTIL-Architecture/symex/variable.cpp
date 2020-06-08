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
#include "variable.hpp"
#include "../trace/tracer.hpp"
#include "../routine/call_convention.hpp"

namespace vtil::symbolic
{
	// Dummy iterator to be used when variable is not being tracked within a block.
	//
	static const il_const_iterator free_form_iterator = [ ] ()
	{
		// Create a dummy invalid block with an invalid instruction and reference it.
		//
		static basic_block dummy_block;
		dummy_block.stream.push_back( {} );
		return dummy_block.begin();
	}();
	
	// Returns the origin block of the pointer.
	//
	static const basic_block* get_pointer_origin( const symbolic::expression& exp )
	{
		// If variable with valid iterator, return the block.
		//
		if ( exp.is_variable() )
		{
			auto& var = exp.uid.get<symbolic::variable>();
			if ( var.at.is_valid() )
				return var.at.container;
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
	static void fill_displacement( access_details* details, const pointer& p1, const pointer& p2, tracer* tracer )
	{
		// If valid tracer provided:
		//
		if ( tracer )
		{
			// If two pointers' origins mismatch, propagate first.
			//
			auto o1 = get_pointer_origin( p1.base );
			auto o2 = get_pointer_origin( p2.base );
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
					symbolic::expression base = in->base;
					base.transform( [ & ] ( symbolic::expression& exp )
					{
						// Skip if not variable.
						//
						if ( !exp.is_variable() )
							return;
						variable var = exp.uid.get<variable>();

						// Skip if it has an invalid iterator.
						//
						if ( !var.at.is_valid() )
							return;

						// Determine all paths and path restrict the iterator.
						//
						auto pathset_1 = il_const_iterator::path_to( var.at.container, o1, false );
						auto pathset_2 = il_const_iterator::path_to( var.at.container, o2, false );
						var.at.is_path_restricted = true;

						// If only one of the paths are valid for backwards iteration:
						//
						if ( pathset_1.empty() ^ pathset_2.empty() )
						{
							// Set the restriction.
							//
							var.at.is_path_restricted = true;
							var.at.paths_allowed = pathset_1.empty() ? pathset_2 : pathset_1;
							exp = tracer->rtrace( std::move( var ) );
						}
						// If both paths are valid for backwards iteration:
						//
						else if( pathset_1.size() && pathset_2.size() )
						{
							// Calculate for both and set if equivalent.
							//
							var.at.paths_allowed = pathset_1;
							auto exp1 = tracer->rtrace( var );
							var.at.paths_allowed = pathset_2;
							auto exp2 = tracer->rtrace( var );
							if ( exp1.equals( exp2 ) )
								exp = exp1;
						}
					} );

					// Write the new pointer.
					//
					*out = pointer{ base };
				}

				// Recurse with the new pointers.
				//
				return fill_displacement( details, pn1, pn2, nullptr );
			}
		}

		// If the two pointers can overlap (not restrict qualified against each other),
		// write dummy bit count and the offset if we can calculate it.
		//
		if ( p1.can_overlap( p2 ) )
		{
			details->bit_count = -1;
			if ( auto disp = p1 - p2 )
				details->bit_offset = ( bitcnt_t ) *disp * 8;
			else
				details->bit_offset = -1;
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
	static access_details test_access( const variable& var, const il_const_iterator& it, tracer* tracer, bool write, bool read )
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
				return access_details{
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
			if ( it->base->accesses_memory() )
			{
				// If access type matches:
				//
				if ( ( write && it->base->writes_memory() ) ||
					 ( read && !it->base->writes_memory() ) )
				{
					// Generate an expression for the pointer.
					//
					auto [base, offset] = it->memory_location();
					pointer ptr = { tracer->trace( { it, base } ) + offset };

					// Calculate displacement.
					//
					access_details details;
					fill_displacement( &details, ptr, mem->base, tracer );

					// If pointers can indeed overlap:
					//
					if ( details )
					{
						// Fill read/write.
						//
						details.read = !it->base->writes_memory();
						details.write = it->base->writes_memory();

						// If offset is unknown, return as is.
						//
						if ( details.is_unknown() )
							return details;

						// Check if within boundaries, set bit count and return if so.
						//
						bitcnt_t low_offset = details.bit_offset;
						bitcnt_t high_offset = low_offset + ( bitcnt_t ) it->access_size() * 8;
						if ( low_offset < mem->bit_count && high_offset > 0 )
						{
							details.bit_count = ( bitcnt_t ) it->access_size() * 8;
							return details;
						}
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
			call_convention cc = it.container->owner
				? it.container->owner->get_cconv( it->vip )
				: default_call_convention;

			// If variable is a register:
			//
			if ( var.is_register() )
			{
				const register_desc& reg = var.reg();

				// If exiting the virtual machine:
				//
				if ( *it->base == ins::vexit )
				{
					// If checking for write only, return no-acccess.
					//
					if( write )
						return access_details{ .bit_count = 0, .read = false, .write = false };

					// If retval register, indicate read from:
					//
					for ( const register_desc& retval : it.container->owner->routine_convention.retval_registers )
					{
						if ( retval.overlaps( reg ) )
						{
							return access_details{
								.bit_offset = retval.bit_offset - reg.bit_offset,
								.bit_count = retval.bit_count,
								.read = true, 
								.write = false
							};
						}
					}

					// If volatile register, indicate discarded:
					//
					for ( const register_desc& retval : it.container->owner->routine_convention.volatile_registers )
					{
						if ( retval.overlaps( reg ) )
							return access_details{ .bit_count = 0, .read = false, .write = false };
					}
				
					// Otherwise indicate read from.
					//
					return access_details{
						.bit_offset = 0,
						.bit_count = reg.bit_count,
						.read = true, 
						.write = false
					};

					// If virtual register, indicate it's discarded.
					//
					if ( reg.is_virtual() )
					{
						if ( !read )
							return access_details{ .bit_offset = 0, .bit_count = reg.bit_count, .read = false, .write = true };
						else
							return access_details{ .bit_count = 0, .read = false, .write = false };
					}
				}

				// If not only looking for read access, check if register is written to.
				//
				access_details wdetails = { .bit_count = 0 };
				if ( !read )
				{
					for ( const register_desc& param : cc.volatile_registers )
					{
						if ( param.overlaps( reg ) )
						{
							wdetails.bit_offset = param.bit_offset - reg.bit_offset;
							wdetails.bit_count = param.bit_count;
							break;
						}
					}
					for ( const register_desc& retval : cc.retval_registers )
					{
						if ( retval.overlaps( reg ) )
						{
							wdetails.bit_offset = retval.bit_offset - reg.bit_offset;
							wdetails.bit_count = retval.bit_count;
							break;
						}
					}
				}

				// If not only looking for write access, check if register is read from.
				//
				access_details rdetails = { .bit_count = 0 };
				if ( !write )
				{
					for ( const register_desc& param : cc.param_registers )
					{
						if ( param.overlaps( reg ) )
						{
							rdetails.bit_offset = param.bit_offset - reg.bit_offset;
							rdetails.bit_count = param.bit_count;
							break;
						}
					}
				}

				// Merge rdetails and wdetails, return.
				//
				if ( !wdetails ) return rdetails;
				if ( !rdetails ) return wdetails;
				return access_details{
					.bit_offset = std::min( wdetails.bit_offset, rdetails.bit_offset ),
					.bit_count = std::max( wdetails.bit_count, rdetails.bit_count ),
					.read = true,
					.write = true
				};
			}
			// If variable is memory, report unknown access. (TODO: Propper parsing!)
			//
			else
			{
				return access_details{ .bit_offset = -1, .bit_count = -1 };
			}
		}

		// No access case.
		//
		return access_details{ .bit_count = 0, .read = false, .write = false };
	}

	// Constructs by iterator and the variable descriptor itself.
	//
	variable::variable( const il_const_iterator& it, descriptor_t desc ) :
		descriptor( std::move( desc ) ), at( it )
	{
		// If read-only register, remove the iterator.
		//
		if ( is_register() && reg().is_read_only() )
			at = {};

		// Validate the variable.
		//
		fassert( is_valid() );
	}
	
	// Construct free-form with only the descriptor itself.
	//
	variable::variable( descriptor_t desc ) 
		: variable( free_form_iterator, std::move( desc ) ) {}

	// Returns whether the variable is valid or not.
	//
	bool variable::is_valid() const
	{
		// If register:
		//
		if ( auto* reg = std::get_if<register_t>( &descriptor ) )
		{
			// Iterator must be valid if not read-only.
			//
			if ( !at.is_valid() && !reg->is_read_only() )
				return false;

			// Redirect to register descriptor validation.
			//
			return reg->is_valid();
		}
		// If memory:
		//
		else
		{
			auto& mem = std::get<memory_t>( descriptor );

			// Iterator must be valid.
			//
			if ( !at.is_valid() )
				return false;

			// Must have a valid pointer of 64 bits.
			//
			if ( !mem.base.base || mem.base.base.size() != 64 )
				return false;

			// Bit count should be within (0, 64] and byte-addressable.
			//
			return 0 < mem.bit_count && 
				   mem.bit_count <= 64 && 
				   ( mem.bit_count & 7 ) == 0;
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
		expression&& tmp = variable{ at, register_desc{ src.flags, src.local_id, 64 } }.to_expression( false );
		return ( src.bit_offset ? tmp >> src.bit_offset : tmp ).resize( src.bit_count );
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
		base = format::str( "%s#0x%llx", base, at.container->entry_vip );

		// Append the stream index and return.
		//
		if ( at.is_begin() )    return base + "?";
		else if ( at.is_end() ) return base + "*";
		else                    return base + "." + std::to_string( std::distance( at.container->begin(), at ) );
	}

	// Packs all the variables in the expression where it'd be optimal.
	//
	expression variable::pack_all( const expression& ref )
	{
		// List of ideal packers.
		//
		static constexpr std::pair<bitcnt_t, bitcnt_t> ideal_packers[] =
		{
			{ 1,  0 }, // Any boolean register.
			{ 8,  0 }, // Low byte,  e.g. AL.
			{ 8,  8 }, // High byte, e.g. AH.
			{ 16, 0 }, // Low word,  e.g. AX.
			{ 32, 0 }, // Low dword, e.g. EAX.
		};

		// Copy expression and recurse into it.
		//
		expression exp = ref;
		exp.transform( [ ] ( expression& exp )
		{
			// Skip if expression has any known 1s.
			//
			if ( exp.known_one() )
				return;

			// Skip if expression does not have exactly one variable.
			//
			if ( exp.count_unique_variables() != 1 )
				return;

			// Check if the unknown mask matches that of an ideal packer.
			//
			auto it = std::find_if( ideal_packers, std::end( ideal_packers ), [ & ] ( auto& pair )
			{
				return math::fill( pair.first ) == exp.unknown_mask();
			} );
			if ( it == std::end( ideal_packers ) )
				return;

			// Clone and resize the expression.
			//
			auto exp_resized = exp.clone().resize( it->first );

			// If top node is not __ucast, skip.
			//
			if ( exp_resized.op != math::operator_id::ucast )
				return;

			// Until we reach the end of the list and the size is the same:
			//
			for ( ; it != std::end( ideal_packers ) && it->first == exp_resized.size(); it++ )
			{
				auto node = exp_resized.lhs;

				// If expected bit offset is non-zero:
				//
				if ( it->second != 0 )
				{
					// If node is not shift right, skip.
					//
					if ( node->op != math::operator_id::shift_right )
						continue;

					// If node is not shifting as expected, skip.
					//
					if ( !node->rhs->equals( it->second ) )
						continue;

					// Skip to the real operand.
					//
					node = node->lhs;
				}

				// Skip if top node is not a variable.
				//
				if ( !node->is_variable() )
					continue;

				// Break if the variable is not a register.
				//
				const variable& var = node->uid.get<variable>();
				if ( !var.is_register() )
					break;

				// Break if cannot be fit.
				//
				const register_desc& reg = var.reg();
				if ( reg.bit_count < it->first )
					break;

				// Found a match, rewrite the expression and stop iterating.
				//
				variable var_new = var;
				var_new.reg().bit_count = it->first;
				var_new.reg().bit_offset += it->second;
				exp = expression{ var_new, it->first }.resize( exp.size() );
				break;
			}
		} );
		return exp;
	}

	// Checks if the variable is read by / written by the given instruction, 
	// returns nullopt it could not be known at compile-time, otherwise the
	// access details as described by access_details. Tracer is used for
	// pointer resolving, if nullptr passed will use default tracer.
	//
	access_details variable::read_by( const il_const_iterator& it, tracer* tr ) const
	{
		tracer default_tracer;
		if ( !tr ) tr = &default_tracer;
		return test_access( *this, it, tr ? tr : &default_tracer, false, true );
	}
	access_details variable::written_by( const il_const_iterator& it, tracer* tr ) const
	{
		tracer default_tracer;
		if ( !tr ) tr = &default_tracer;
		return test_access( *this, it, tr ? tr : &default_tracer, true, false );
	}
	access_details variable::accessed_by( const il_const_iterator& it, tracer* tr ) const
	{
		tracer default_tracer;
		if ( !tr ) tr = &default_tracer;
		return test_access( *this, it, tr ? tr : &default_tracer, false, false );
	}
};