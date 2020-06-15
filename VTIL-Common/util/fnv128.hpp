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
#pragma once
#include <string>
#include <array>
#include <functional>
#include <cstring>
#include "mul128.hpp"
#include "../io/formatting.hpp"

namespace vtil
{
	// Defines a 128-bit hash type based on FNV-1.
	//
	struct fnv128_hash_t
	{
		// Magic constants for 128-bit FNV-1 .
		//
		using value_t = uint64_t;
		static constexpr value_t default_seed[] = { 0x62B821756295C58D, 0x6C62272E07BB0142 };
		static constexpr value_t prime[] =        { 0x000000000000013B, 0x0000000001000000 };

		// Current value of the hash.
		//
		value_t value[ 2 ];

		// Construct a new hash from an optional seed of either 64-bit or 128-bit value.
		//
		fnv128_hash_t( value_t seed64 ) { value[ 1 ] = ~0ull; value[ 0 ] = seed64; }
		fnv128_hash_t( const value_t( &seed128 )[ 2 ] = default_seed ) { std::copy( seed128, std::end( seed128 ), value ); }

		// Appends the given array of bytes into the hash value.
		//
		template<typename T>
		void add_bytes( const T& data )
		{
			const uint8_t* bytes = ( const uint8_t* ) &data;

			for ( size_t i = 0; i != sizeof( T ); i++ )
			{
				// Apply XOR over the low byte.
				//
				value[ 0 ] ^= bytes[ i ];

				// Calculate [value * prime].
				//
				// A: 0x???????????????? 0x????????????????
				//                    HA                 LA
				uint64_t ha = value[ 1 ], la = value[ 0 ];
				// B: 0x0000000001000000 0x000000000000013B
				//                    HB                 LB
				uint64_t hb = prime[ 1 ], lb = prime[ 0 ];
				//                                        x
				// ----------------------------------------
				// = (HA<<64 + LA) * (HB<<64 + LB)
				//
				// = LA     * LB       (Has both low and high parts)
				//
				value[ 0 ] = _umul128( la, lb, &value[ 1 ] );
				//
				//   HA<<64 * HB<<64 + (Discarded)
				//   HA<<64 * LB     + (Will have no low part)
				//
				value[ 1 ] += ha * lb;
				//
				//   LA     * HB<<64 + (Will have no low part)
				//
				value[ 1 ] += la * hb;
			}
		}

		// Implicit conversion to 64-bit and 128-bit values.
		//
		uint64_t as64() const { return value[ 0 ] + value[ 1 ]; }
		operator uint64_t() const { return as64(); }

		// Conversion to human-readable format.
		//
		std::string to_string() const
		{
			return format::str( "0x%p%p", value[ 1 ], value[ 0 ] );
		}

		// Basic comparison operators.
		//
		bool operator<( const fnv128_hash_t& o ) const  { return memcmp( value, o.value, sizeof( value ) ) < 0; }
		bool operator==( const fnv128_hash_t& o ) const { return memcmp( value, o.value, sizeof( value ) ) == 0; }
		bool operator!=( const fnv128_hash_t& o ) const { return memcmp( value, o.value, sizeof( value ) ) != 0; }
	};
};

// Make it std::hashable.
//
namespace std
{
	template<>
	struct hash<vtil::fnv128_hash_t>
	{
		size_t operator()( const vtil::fnv128_hash_t& value ) const { return ( size_t ) value.as64(); }
	};
};