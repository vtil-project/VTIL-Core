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
#include <iterator>
#include "../math/bitwise.hpp"
#ifdef _MSC_VER
	#include <intrin.h>
#endif

namespace vtil
{
	// Declares a bitmap of size N with fast search helpers.
	//
	template<size_t N>
	struct bitmap
	{
		// Declare invalid iterator and block count.
		//
		static constexpr size_t npos = math::bit_npos;
		static constexpr size_t block_count = ( N + 63 ) / 64;

		// Store the bits, initialized to zero.
		//
		uint64_t blocks[ block_count ] = { 0 };

		// Default construction / copy / move.
		//
		bitmap() = default;
		bitmap( bitmap&& ) = default;
		bitmap( const bitmap& ) = default;
		bitmap& operator=( bitmap&& ) = default;
		bitmap& operator=( const bitmap& ) = default;

		// Find any bit with the given value in the array.
		//
		size_t find( bool value ) const
		{
			// Invoke find bit.
			//
			size_t idx = math::find_bit( std::begin( blocks ), std::end( blocks ), value );
			
			// If block has leftovers, adjust for overflow.
			//
			if constexpr ( ( block_count * 64 ) != N )
			{
				if ( idx > N )
					idx = math::bit_npos;
			}

			// Return the index.
			//
			return idx;
		}

		// Gets the value of the Nth bit.
		//
		bool get( size_t n ) const
		{
			dassert( n < N );
#ifdef _MSC_VER
			return _bittest64( ( long long* ) blocks + ( n / 64 ), n & 63 );
#else
			return blocks[ n / 64 ] & ( 1ull << ( n & 63 ) );
#endif
		}

		// Sets the value of the Nth bit.
		//
		bool set( size_t n, bool v )
		{
			dassert( n < N );
#ifdef _MSC_VER
			if ( v ) return _bittestandset64( ( long long* ) blocks + ( n / 64 ), n & 63 );
			else     return _bittestandreset64( ( long long* ) blocks + ( n / 64 ), n & 63 );
#else
			uint64_t& block = blocks[ n / 64 ];
			size_t mask = ( 1ull << ( n & 63 ) );
			
			bool retval = block & mask;
			if ( v ) block |= mask;
			else     block &= ~mask;
			
			return retval;
#endif
		}
	};
};