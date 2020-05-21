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

namespace vtil::optimizer
{
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
			if ( !mem.pointer || mem.pointer->size() != 64 )
				return false;

			// Bit count should be within (0, 64] and byte-addressable.
			//
			return 0 < mem.bit_count && 
				   mem.bit_count <= 64 && 
				   ( mem.bit_count & 7 ) == 0;
		}
	}


	// Conversion to symbolic expression.
	//
	symbolic::expression variable::to_expression( bool unpack ) const
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
		symbolic::expression&& tmp = variable{ at, register_desc{ src.flags, src.local_id, 64 } }.to_expression( false );
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
			base = format::str( "[%s]", mem->pointer->to_string() );

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
	symbolic::expression variable::pack_all( const symbolic::expression& ref )
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
		symbolic::expression exp = ref;
		exp.transform( [ ] ( symbolic::expression& exp )
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
				exp = symbolic::expression{ var_new, it->first }.resize( exp.size() );
				break;
			}
		} );
		return exp;
	}
};