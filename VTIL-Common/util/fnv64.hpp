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
#pragma once
#include <string>
#include <array>
#include <functional>
#include <cstring>
#include "../io/formatting.hpp"

namespace vtil
{
	// Defines a 64-bit hash type based on FNV-1.
	//
	struct fnv64_hash_t
	{
		// Magic constants for 64-bit FNV-1 .
		//
		using value_t = uint64_t;
		static constexpr value_t default_seed = { 0xCBF29CE484222325 };
		static constexpr value_t prime =        { 0x00000100000001B3 };

		// Current value of the hash.
		//
		value_t value[ 1 ];

		// Construct a new hash from an optional seed of 64-bit value.
		//
		fnv64_hash_t( value_t seed64 = default_seed ) { value[ 0 ] = seed64; }

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
				value[ 0 ] *= prime;
			}
		}

		// Implicit conversion to 64-bit values.
		//
		uint64_t as64() const { return value[ 0 ]; }
		operator uint64_t() const { return as64(); }

		// Conversion to human-readable format.
		//
		std::string to_string() const
		{
			return format::str( "0x%p", value[ 0 ] );
		}

		// Basic comparison operators.
		//
		bool operator<( const fnv64_hash_t& o ) const  { return memcmp( value, o.value, sizeof( value ) ) < 0; }
		bool operator==( const fnv64_hash_t& o ) const { return memcmp( value, o.value, sizeof( value ) ) == 0; }
		bool operator!=( const fnv64_hash_t& o ) const { return memcmp( value, o.value, sizeof( value ) ) != 0; }
	};
};

// Make it std::hashable.
//
namespace std
{
	template<>
	struct hash<vtil::fnv64_hash_t>
	{
		size_t operator()( const vtil::fnv64_hash_t& value ) const { return ( size_t ) value.as64(); }
	};
};