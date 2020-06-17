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
#include <iterator>
#include <limits>

namespace vtil
{
	template<typename _value_type = size_t>
	struct numeric_range
	{
		// Declare the iterator type.
		//
		struct iterator_end_tag_t {};
		struct iterator
		{
			// Generic iterator typedefs.
			//
			using iterator_category = std::bidirectional_iterator_tag;
			using value_type =        _value_type;
			using difference_type =   size_t;
			using pointer =           value_type*;
			using reference =         value_type&;

			// Range of iteration.
			//
			value_type at;
			value_type limit;

			// Default constructor.
			//
			iterator( value_type at, value_type limit = 0 ) :
				at( at ), value_type( limit ) {}

			// Support bidirectional iteration.
			//
			iterator& operator++() { at++; return *this; }
			iterator& operator--() { at--; return *this; }

			// Equality check against another iterator.
			//
			bool operator==( const iterator& other ) const 
			{ 
				return at == other.at && limit == other.limit;
			}
			bool operator!=( const iterator& other ) const 
			{ 
				return at != other.at || limit != other.limit;
			}
			
			// Equality check against special end iterator.
			//
			bool operator==( iterator_end_tag_t ) const { return at == limit; }
			bool operator!=( iterator_end_tag_t ) const { return at != limit; }

			// Redirect dereferencing to container.
			//
			value_type operator*() { return at; }
			value_type operator*() const { return at; }
		};
		using const_iterator = iterator;

		// Beginning and the end of the range.
		//
		_value_type rng_begin;
		_value_type rng_end;

		// Generic container helpers.
		//
		size_t size() const { return rng_end - rng_begin; }
		iterator begin() const { return { rng_begin, rng_end }; }
		iterator_end_tag_t end() const { return {}; }
		_value_type operator[]( size_t n ) const { return rng_begin + n; }
	};

	// Simple range creation wrapper.
	//
	static const numeric_range<>& iindices() 
	{
		static const numeric_range<> cnt = { 0, SIZE_MAX };
		return cnt;
	};
	template<typename T>
	static numeric_range<T> iiota( T x ) { return { x, std::numeric_limits<T>::max() }; }
};