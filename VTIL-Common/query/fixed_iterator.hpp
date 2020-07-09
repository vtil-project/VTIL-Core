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
#include <vector>
#include <iterator>
#include <utility>
#include <type_traits>
#include "../io/asserts.hpp"
#include "range_iterator.hpp"

// Fixed iterators are used to create simple iterators that are valid range iterators
// from a structure that is not based on a container, but still benefits from a common
// enumeration method and vtil::query system.
//
namespace vtil::query
{
	// Implement a fixed iterator end that redirects comparison to .is_end(), 
	// in a similar way to how nullptr and nullopt works
	//
	struct fixed_iterator_end_t
	{
		struct _tag {};
		constexpr explicit fixed_iterator_end_t( _tag ) {}
	};
	static constexpr fixed_iterator_end_t fixed_iterator_end{ fixed_iterator_end_t::_tag{} };

	// If vector entries are not pointers, they will be used to generate
	// fake const_iterators mapping to each entry.
	//
	template<typename _container_type, typename _value_type>
	struct fixed_iterator
	{
		// Export the required traits of range iterators.
		//
		using container_type = _container_type;
		using value_type = _value_type;
		using iterator_type = const value_type*;
		using recurse_function = std::vector<fixed_iterator>(*)( container_type* self, bool forward );

		// Export the required traits of an standard iterator.
		//
		using iterator_category = std::random_access_iterator_tag;
		using difference_type = size_t;
		using pointer = const value_type*;
		using reference = const value_type&;

		// Fixed iterator consists of a container, a vector that 
		// holds the values to be iterated, and a optional recursion
		// helper that describes what to do on a recursion attempt.
		//
		container_type* container = nullptr;
		std::vector<value_type> fixed_range = {};
		recurse_function recurse_helper = nullptr;
		size_t at = 0;

		// Implement basic requirements of range iterators and data access.
		//
		reference operator*() const { return fixed_range[ at ]; }
		pointer operator->() const { return &fixed_range[ at ]; }
		bool is_end() const { return at == fixed_range.size(); }
		bool is_begin() const { return at == 0; }
		bool is_valid() const { return container && at < fixed_range.size(); }

		// Redirect to helper where relevant, if not return empty vector.
		//
		std::vector<fixed_iterator> recurse( bool forward ) const 
		{ 
			if ( !container || !recurse_helper )
				return {};
			return recurse_helper( container, forward );
		}
	};

	// If vector entries are pointers, they will be used to generate
	// fake iterators mapping to the address pointed by each entry instead.
	//
	template<typename _container_type, typename _value_type>
	struct fixed_iterator<_container_type, _value_type*>
	{
		// Export the required traits of range iterators.
		//
		using container_type = _container_type;
		using value_type = _value_type;
		using iterator_type = value_type*;
		using recurse_function = std::vector<fixed_iterator>(*)(container_type* self, bool forward);

		// Export the required traits of an standard iterator.
		//
		using iterator_category = std::random_access_iterator_tag;
		using difference_type = size_t;
		using pointer = value_type*;
		using reference = value_type&;

		// Fixed iterator consists of a container, a vector that 
		// holds the values to be iterated, and a optional recursion
		// helper that describes what to do on a recursion attempt.
		//
		container_type* container = nullptr;
		std::vector<value_type*> fixed_range = {};
		recurse_function recurse_helper = nullptr;
		size_t at = 0;

		// Implement basic requirements of range iterators and data access.
		//
		reference operator*() const { return *fixed_range[ at ]; }
		value_type operator->() const { return fixed_range[ at ]; }
		bool is_end() const { return at == fixed_range.size(); }
		bool is_begin() const { return at == 0; }
		bool is_valid() const { return container && at < fixed_range.size(); }

		// Redirect to helper where relevant, if not return empty vector.
		//
		std::vector<fixed_iterator> recurse( bool forward ) const
		{
			if ( !container || !recurse_helper )
				return {};
			return recurse_helper( container, forward );
		}
	};
};

// Implement random-access iterator properties, by redirecting to size_t ::at.
//
template<typename container_type, typename value_type>
static auto& operator+=( vtil::query::fixed_iterator<container_type, value_type>& a, size_t i ) { a.at += i; return a; }
template<typename container_type, typename value_type>
static auto& operator++( vtil::query::fixed_iterator<container_type, value_type>& a ) { a.at++; return a; }
template<typename container_type, typename value_type>
static auto& operator--( vtil::query::fixed_iterator<container_type, value_type>& a ) { a.at--; return a; }
template<typename container_type, typename value_type>
static size_t operator-( const vtil::query::fixed_iterator<container_type, value_type>& a, 
						 const vtil::query::fixed_iterator<container_type, value_type>& b )
{
	fassert( a.container == b.container && a.fixed_range == b.fixed_range );
	return a.at - b.at;
}

// Implement equality comparison between same type and the end type.
//
template<typename container_type, typename value_type, typename compared_type>
static bool operator==( const vtil::query::fixed_iterator<container_type, value_type>& a, compared_type&& b )
{
	// Assert sanity of the comparison.
	//
	constexpr bool compare_w_fixed_end = std::is_same_v<std::remove_cvref_t<compared_type>, vtil::query::fixed_iterator_end_t>;
	constexpr bool compare_w_iterator =  std::is_same_v<std::remove_cvref_t<compared_type>, vtil::query::fixed_iterator<container_type, value_type>>;
	static_assert( compare_w_fixed_end || compare_w_iterator, "Invalid fixed type comparison." );

	// If comparing against fixed_iteartor_end, just check if a is at the end.
	//
	if constexpr ( compare_w_fixed_end )
		return a.is_end();

	// Othewrise compare every property.
	//
	if constexpr( compare_w_iterator )
		return a.container == b.container && a.fixed_range == b.fixed_range && a.at == b.at;

}
template<typename container_type, typename value_type, typename compared_type>
static bool operator!=( const vtil::query::fixed_iterator<container_type, value_type>& a, compared_type&& b ) { return !operator==( a, std::forward<compared_type>( b ) ); }