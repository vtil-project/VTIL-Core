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
	namespace impl
	{
		struct no_transform 
		{
			template<typename T>
			T operator()( T&& x ) const noexcept { return x; }
		};

		// Declare a proxying range container.
		//
		template<typename base_iterator, typename F>
		struct range_proxy
		{
			// Declare proxying iterator.
			//
			struct iterator : base_iterator
			{
				// Modify certain traits.
				//
				using reference =         decltype( std::declval<F>()( std::declval<typename base_iterator::reference>() ) );
				using value_type =        typename std::remove_reference_t<reference>;
				
				// Constructed by the original iterator and a reference to transformation function.
				//
				const F& transform;
				constexpr iterator( base_iterator&& i,      const F& transform ) : base_iterator( std::move( i ) ), transform( transform ) {}
				constexpr iterator( const base_iterator& i, const F& transform ) : base_iterator( i ),              transform( transform ) {}

				// Override accessor to apply transformation where relevant.
				//
				reference operator*() const { return transform( base_iterator::operator*() ); }

				// Inherit rest from operator base.
				//
				using base_iterator::operator==;
				using base_iterator::operator!=;
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
			constexpr size_t size() const    { return ( size_t ) std::distance( begin(), end() ); }
		};

		template<typename I, typename F>
		range_proxy( F, I, I )->range_proxy<I, F>;
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
	static constexpr auto view_transformed( C&& container, Fn&& f )
	{
		return impl::range_proxy<decltype( std::begin( container ) ), Fn>{
			std::forward<Fn>( f ),
			std::begin( container ),
			std::end( container )
		};
	}
};