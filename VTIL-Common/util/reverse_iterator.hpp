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
#include <type_traits>
#include "type_helpers.hpp"

namespace vtil
{
	// Reversed iterator wrapper.
	//
	struct reversed_iterator_end_tag {};
	template<typename iterator>
	struct reversed_iterator : iterator
	{
		// Limit, equal to .begin() and whether it was reached or not.
		//
		iterator limit;
		bool at_limit = false;

		// Constructed by the original iterator type and the limit.
		//
		constexpr reversed_iterator( const iterator& i, const iterator& limit )
			: iterator( i ), limit( limit ) {}
		constexpr reversed_iterator( iterator&& i, iterator&& limit )
			: iterator( std::move( i ) ), limit( std::move( limit ) ) {}

		// Default copy/move.
		//
		constexpr reversed_iterator( reversed_iterator&& ) = default;
		constexpr reversed_iterator( const reversed_iterator& ) = default;
		constexpr reversed_iterator& operator=( reversed_iterator&& ) = default;
		constexpr reversed_iterator& operator=( const reversed_iterator& ) = default;
		
		// Reverts back to a normal iterator.
		//
		constexpr iterator& revert() { return *this; }
		constexpr const iterator& revert() const { return *this; }

		// Reverse inc/dec.
		//
		constexpr reversed_iterator& operator--()
		{ 
			// Invoke inc, make sure it returns a reference and return self.
			//
			auto& _ = iterator::operator++();
			return *this;
		}
		constexpr reversed_iterator& operator++()
		{ 
			// If equal to the limit, set limit and return as is.
			//
			if ( operator==( limit ) )
			{
				at_limit = true;
				return *this;
			}

			// Otherwise invoke dec, make sure it returns a reference and return self.
			//
			auto& _ = iterator::operator--();
			return *this;
		}
		constexpr reversed_iterator operator++( int ) { auto s = *this; operator--(); return s; }
		constexpr reversed_iterator operator--( int ) { auto s = *this; operator++(); return s; }

		// Implement (not-)equals operator with the special end tag.
		//
		constexpr bool operator==( reversed_iterator_end_tag ) const { return at_limit; }
		constexpr bool operator!=( reversed_iterator_end_tag ) const { return !at_limit; }

		// Inherit rest from operator base.
		//
		using iterator::operator==;
		using iterator::operator!=;
	};

	// Returns a tuple that behaves equivalent to .rbegin and .rend.
	//
	template<Iterable T>
	static constexpr auto reverse_iterators( T&& cont )
	{
		using iterator_type = decltype( cont.begin() );
		return std::pair {
			reversed_iterator<iterator_type>{ std::prev( std::end( cont ) ), std::begin( cont ) },
			reversed_iterator_end_tag{}
		};
	}

	// Reverses entire container iteration.
	//
	namespace impl
	{
		template<typename T>
		struct reversed_container_proxy;

		template<ReverseIterable T>
		struct reversed_container_proxy<T>
		{
			T container;
			decltype( auto ) begin() { return std::rbegin( container ); }
			decltype( auto ) end() { return std::rend( container ); }
		};
		
		template<Iterable T> requires ( !ReverseIterable<T> )
		struct reversed_container_proxy<T>
		{
			T container;
			decltype( auto ) begin() { return reverse_iterators( container ).first; }
			decltype( auto ) end()   { return reverse_iterators( container ).second; }
		};
	};
	template<Iterable T>
	static constexpr auto backwards( T&& container )
	{
		return impl::reversed_container_proxy<T>{ std::forward<T>( container ) };
	}
};