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
#include "pointer.hpp"
#include <numeric>
#include <vtil/math>
#include "../arch/register_desc.hpp"
#include "variable.hpp"

namespace vtil::symbolic
{
	// Magic value substituting for invalid xpointers.
	//
	static constexpr uint64_t invalid_xpointer = make_crandom();

	// List of keys used for xpointer generation.
	//
	static constexpr std::array xpointer_keys = make_crandom_n<VTIL_SYM_PTR_XPTR_KEYS>( 1 );

	// Pointer bases we explicitly declare restricted.
	//
	static constexpr register_flag restricted_pointers[] = {
		register_stack_pointer,
		register_image_base
	};

	// Construct from symbolic expression.
	//
	pointer::pointer( expression&& _base ) : base( std::move( _base ) )
	{
		// Determine pointer strength and the flags. Pointer is weak if it has unknowns 
		// apart from the special restricted registers allowed.
		//
		strenght = base.evaluate( [ & ] ( const unique_identifier& uid )
								 -> std::optional<uint64_t>
		{
			// Fail evaluation if the variable is a memory destination.
			//
			const variable& var = uid.get<variable>();
			if ( !var.is_register() )
				return std::nullopt;

			// If register is a restricted pointer, append the flag
			// to the current flags list and return zero.
			//
			for ( auto flag : restricted_pointers )
			{
				if ( ( var.reg().flags & flag ) == flag )
				{
					flags |= flag;
					return 0;
				}
			}

			// Otherwise fail evaluation.
			//
			return std::nullopt;
		} ).is_unknown() ? -1 : +1;

		// Initialize X-Pointers.
		//
		for ( auto [xptr, key] : zip( xpointer, xpointer_keys ) )
		{
			xptr = base.get( [ k = uint64_t( key ) ]( const unique_identifier& uid )
			{
				// Hash the identifier of the value with the current key and mask it.
				//
				const variable& var = uid.get<variable>();
				if ( var.is_register() )
				{
					const variable::register_t& reg = var.reg();
					uint64_t pseudo_pointer = make_hash( reg.flags, reg.bit_offset, reg.local_id, k ).as64();
					return pseudo_pointer & math::fill( reg.bit_count );
				}
				else
				{
					const variable::memory_t& mem = var.mem();
					uint64_t pseudo_pointer = combine_hash( var.hash(), hash_t{ k } ).as64();
					return pseudo_pointer & math::fill( mem.bit_count );
				}
			} ).value_or( invalid_xpointer );
		}
	}

	// Simple pointer offseting.
	//
	pointer pointer::operator+( int64_t dst ) const
	{
		pointer copy = *this;
		copy.base = std::move( copy.base ).decay() + dst;
		std::transform(
			std::begin( xpointer ), std::end( xpointer ),
			std::begin( copy.xpointer ),
			[ = ] ( auto v ) { return v + dst; }
		);
		return copy;
	}

	// Calculates the distance between two pointers as an optional constant.
	//
	std::optional<int64_t> pointer::operator-( const pointer& o ) const
	{
		int64_t delta = xpointer[ 0 ] - o.xpointer[ 0 ];
		for ( size_t n = 1; n < xpointer.size(); n++ )
			if ( ( xpointer[ n ] - o.xpointer[ n ] ) != delta )
				return std::nullopt;

#if VTIL_SYM_PTR_SAFE_DISP
		return ( pointer.decay() - o.pointer.decay() ).get<true>();
#else
		return delta;
#endif
	}
};