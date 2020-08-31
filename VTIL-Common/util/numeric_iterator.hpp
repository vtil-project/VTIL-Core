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
#include <limits>
#include "type_helpers.hpp"

namespace vtil
{
	template<Integral T = size_t>
	struct numeric_range
	{
		// Declare the iterator type.
		//
		struct iterator
		{
			// Generic iterator typedefs.
			//
			using iterator_category = std::bidirectional_iterator_tag;
			using difference_type =   std::make_signed_t<T>;
			using value_type =        T;
			using reference =         T&;
			using pointer =           void*;

			value_type at;

			// Support bidirectional iteration.
			//
			constexpr iterator& operator++() { at++; return *this; }
			constexpr iterator& operator--() { at--; return *this; }
			constexpr iterator operator++( int ) { auto s = *this; operator++(); return s; }
			constexpr iterator operator--( int ) { auto s = *this; operator--(); return s; }

			// Equality check against another iterator.
			//
			constexpr bool operator==( const iterator& other ) const { return at == other.at; }
			constexpr bool operator!=( const iterator& other ) const { return at != other.at; }
			
			// Redirect dereferencing to container.
			//
			constexpr value_type operator*() const { return at; }
		};
		using const_iterator = iterator;

		// Beginning and the end of the range.
		//
		T min_value;
		T max_value;

		constexpr numeric_range( T min_value = std::numeric_limits<T>::min(),
					             T max_value = std::numeric_limits<T>::max() ) 
			: min_value( min_value ), max_value( max_value ) {}

		// Generic container helpers.
		//
		constexpr size_t size() const { return max_value - min_value; }
		constexpr iterator begin() const { return { min_value }; }
		constexpr iterator end() const   { return { max_value }; }
		constexpr T operator[]( size_t n ) const { return min_value + n; }
	};
	template<Integral T> numeric_range( T a )      -> numeric_range<T>;
	template<Integral T> numeric_range( T a, T b ) -> numeric_range<T>;

	// Simple range creation wrapper.
	//
	static constexpr numeric_range<> iindices = {};

	template<typename T>
	static numeric_range<T> iiota( T x ) { return { x }; }
};