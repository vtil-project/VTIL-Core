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

// We implement a simple type-traits like template to check if an arbitrary type 
// abides by the range iterator contract.
//
namespace vtil::query
{
	namespace impl
	{
		template<typename _T>
		static constexpr bool _is_range_iterator( bool )
		{
			using T = typename std::remove_cvref_t<_T>;

			/// Must a valid standard random-access iterator.
			// - T::operator+=();
			// - T::operator++();
			// - T::operator--();
			//
			using dist_type = decltype( std::declval<const T>() - std::declval<const T>() );
			using next_type = decltype( std::next( std::declval<const T>() ) );
			using prev_type = decltype( std::prev( std::declval<const T>() ) );
			using dec_type = decltype( --std::declval<T>() );
			using inc_type = decltype( ++std::declval<T>() );
			using ref_type = decltype( std::declval<const T>().operator*() );
			using ptr_type = decltype( std::declval<const T>().operator->() );

			// Must have a public member called .container that is of type T::container_type*.
			// - T::container_type* T::container;
			//
			using container_type_a = std::remove_pointer_t<decltype( std::declval<T>().container )>;
			using container_type_b = typename T::container_type;
			if ( !std::is_same_v<container_type_a, container_type_b> )
				return false;

			// Must have the basic comparison checks implemented.
			// - bool T::operator==(const T& o);
			// - bool T::operator!=(const T& o);
			//
			using comparison_assertation_1 = decltype( bool( std::declval<const T>() == std::declval<const T>() ) );
			using comparison_assertation_2 = decltype( bool( std::declval<const T>() != std::declval<const T>() ) );

			// Must have the container-abstracting range checks implemented.
			// - bool T::is_begin();
			// - bool T::is_end();
			// - bool T::is_valid();
			//
			using range_check_1 = decltype( bool( std::declval<const T>().is_begin() ) );
			using range_check_2 = decltype( bool( std::declval<const T>().is_end() ) );
			using range_check_3 = decltype( bool( std::declval<const T>().is_valid() ) );

			// Must have recursion helpers implemented, even if no-op.
			//
			// - container_type T::recurse(bool)
			//   - container_iterator_type container_type::begin()
			//   - container_iterator_type container_type::end()
			//
			using recurse_retval = decltype( std::declval<const T>().recurse( false ) );
			using container_iterator_begin = decltype( std::declval<recurse_retval>().begin() );
			using container_iterator_end = decltype( std::declval<recurse_retval>().end() );
			using container_iterator_value = std::remove_cvref_t<decltype( *std::declval<container_iterator_begin>() )>;
			using container_iterator_pointer = std::remove_cvref_t<decltype( std::declval<container_iterator_begin>().operator->() )>;

			return std::is_same_v<std::remove_cvref_t<container_iterator_value>, T> && 
				   std::is_same_v<std::remove_cvref_t<container_iterator_pointer>, T*>;
		}

		template<typename T>
		static constexpr bool _is_range_iterator( ... ) { return false; }
	};
	template<typename T>
	static constexpr bool is_range_iterator_v = impl::_is_range_iterator<T>( true );
};