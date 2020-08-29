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
#include "intrinsics.hpp"

namespace vtil
{
	namespace impl
	{
		struct no_transform 
		{
			template<typename T>
			__forceinline T operator()( T&& x ) const noexcept { return x; }
		};

		// Declare a proxying range container.
		//
		template<typename base_iterator, typename F>
		struct range_proxy
		{
			// Declare proxying iterator.
			//
			struct iterator
			{
				// Define iterator traits.
				//
				using iterator_category = typename std::iterator_traits<std::remove_cvref_t<base_iterator>>::iterator_category;
				using difference_type =   typename std::iterator_traits<std::remove_cvref_t<base_iterator>>::difference_type;
				using reference =         decltype( std::declval<F>()( *std::declval<base_iterator>() ) );
				using value_type =        std::remove_reference_t<reference>;
				using pointer =           value_type*;
				
				// Constructed by the original iterator and a reference to transformation function.
				//
				const F& transform;
				base_iterator at;
				constexpr iterator( const base_iterator& i, const F& transform ) : at( i ), transform( transform ) {}

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

				// Override accessor to apply transformation where relevant.
				//
				constexpr reference operator*() const { return transform( *at ); }
			};
			using const_iterator = iterator;

			// Holds transformation begin an end.
			//
			F transform;
			base_iterator ibegin;
			base_iterator iend;

			// Declare basic container interface.
			//
			constexpr iterator begin() const { return { ibegin, transform }; }
			constexpr iterator end() const   { return { iend, transform }; }
			constexpr size_t size() const    { return ( size_t ) std::distance( ibegin, iend ); }
			constexpr decltype( auto ) operator[]( size_t n ) const { return transform( *std::next( ibegin, n ) ); }
		};
	};

	template<typename It, typename Fn>
	static constexpr auto make_range( It&& begin, It&& end, Fn&& f )
	{
		return impl::range_proxy<It, Fn>{
			std::forward<Fn>( f ),
			std::forward<It>( begin ), 
			std::forward<It>( end ) 
		};
	}
	template<typename It>
	static constexpr auto make_range( It&& begin, It&& end )
	{
		return impl::range_proxy<It, impl::no_transform>{
			impl::no_transform{},
			std::forward<It>( begin ), 
			std::forward<It>( end ) 
		};
	}
	template<Iterable C, typename Fn>
	static constexpr auto make_view( C&& container, Fn&& f )
	{
		return impl::range_proxy<decltype( std::begin( container ) ), Fn>{
			std::forward<Fn>( f ),
			std::begin( container ),
			std::end( container )
		};
	}
};