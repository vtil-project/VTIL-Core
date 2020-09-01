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
#include <tuple>
#include <iterator>
#include "type_helpers.hpp"
#include "optional_reference.hpp"

namespace vtil
{
	template<Iterable... Tx>
	struct joint_container
	{
		using iterator_array =  std::tuple<decltype( std::begin( std::declval<const Tx&>() ) )...>;
		using reference_array = std::tuple<decltype( *std::begin( std::declval<const Tx&>() ) )...>;

		// Declare the iterator type.
		//
		struct base_iterator
		{
			// Generic iterator typedefs.
			//
			using iterator_category = std::bidirectional_iterator_tag;
			using difference_type =   int64_t;
			using pointer =           void*;
			using value_type =        reference_array;
			using reference =         reference_array;

			// Iterators.
			//
			iterator_array iterators;

			// Support bidirectional iteration.
			//
			constexpr base_iterator& operator++() { std::apply( [ ] ( auto&... it ) { ( ( ++it ), ... ); }, iterators ); return *this; }
			constexpr base_iterator& operator--() { std::apply( [ ] ( auto&... it ) { ( ( --it ), ... ); }, iterators ); return *this; }
			constexpr base_iterator operator++( int ) { auto s = *this; operator++(); return s; }
			constexpr base_iterator operator--( int ) { auto s = *this; operator--(); return s; }

			// Equality check against another iterator.
			//
			constexpr bool operator==( const base_iterator& other ) const { return std::get<0>( iterators ) == std::get<0>( other.iterators ); }
			constexpr bool operator!=( const base_iterator& other ) const { return std::get<0>( iterators ) != std::get<0>( other.iterators ); }

			// Redirect dereferencing to container.
			//
			constexpr reference_array operator*() const { return std::apply( [ ] ( auto&... it ) { return reference_array{ *it... }; }, iterators ); }
		};
		using iterator =       base_iterator;
		using const_iterator = base_iterator;

		// Tuple containing data sources, length of iteration range, pre-computed begin and end.
		//
		const std::tuple<Tx...> sources;
		const size_t length;
		const iterator begin_p;
		const iterator end_p;

		template<typename... Tv>
		constexpr joint_container( Tv&&... sc )
			: sources( std::forward<Tv>( sc )... ),
			  length(  std::size( std::get<0>( sources ) ) ),
			  begin_p( std::apply( [ & ] ( auto&... src ) { return iterator{ { std::begin( src )... }                      }; }, sources ) ),
			  end_p(   std::apply( [ & ] ( auto&... src ) { return iterator{ { std::next( std::begin( src ), length )... } }; }, sources ) ) {}

		// Generic container interface.
		//
		constexpr size_t size() const     { return length; }
		constexpr iterator begin() const  { return begin_p; }
		constexpr iterator end() const    { return end_p; }
		constexpr decltype( auto ) operator[]( size_t n ) const { return *std::next( begin(), n ); }
	};

	template <Iterable... Tx>
	static constexpr joint_container<Tx...> zip( Tx&&... args ) { return { std::forward<Tx>( args )... }; }
};