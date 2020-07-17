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
#include <type_traits>
#include <array>
#include "intrinsics.hpp"

namespace vtil
{
	// Type tag.
	//
	template<typename T>
	struct type_tag { using type = T; };
	
	// Check for specialization.
	//
	namespace impl
	{
		template <template<typename...> typename Tmp, typename>
		static constexpr bool is_specialization_v = false;
		template <template<typename...> typename Tmp, typename... Tx>
		static constexpr bool is_specialization_v<Tmp, Tmp<Tx...>> = true;
	};
	template <template<typename...> typename Tmp, typename T>
	static constexpr bool is_specialization_v = impl::is_specialization_v<Tmp, std::remove_cvref_t<T>>;

	// Checks if the given lambda can be evaluated in compile time.
	//
	template<typename F, std::enable_if_t<F{}(), int> = 0>
	static constexpr bool is_constexpr( F )   { return true; }
	static constexpr bool is_constexpr( ... ) { return false; }

	// Commonly used concepts.
	//
	template<typename T>
	concept Iterable = requires( T v ) { std::begin( v ); std::end( v ); };
	template<typename T>
	concept Integral = std::is_integral_v<T>;

	// Constructs a static constant given the type and parameters, returns a reference to it.
	//
	namespace impl
	{
		template<typename T, auto... params>
		struct static_allocator { inline static const T value = { params... }; };
	};
	template<typename T, auto... params>
	static constexpr const T& make_static() noexcept { return impl::static_allocator<T, params...>::value; }

	// Default constructs the type and returns a reference to the static allocator. 
	// This useful for many cases, like:
	//  1) Function with return value of (const T&) that returns an external reference or if not applicable, a default value.
	//  2) Using non-constexpr types in constexpr structures by deferring the construction.
	//
	template<typename T> static constexpr const T& make_default() noexcept { return make_static<T>(); }

	// Special type that collapses to a constant reference to the default constructed value of the type.
	//
	static constexpr struct
	{
		template<typename T, std::enable_if_t<!std::is_reference_v<T>, int> = 0>
		constexpr operator const T&() const noexcept { return make_default<T>(); }

		template<typename T, std::enable_if_t<!std::is_reference_v<T>, int> = 0>
		constexpr operator T() const noexcept { static_assert( sizeof( T ) == -1, "Static default immediately decays, unnecessary use." ); unreachable(); }
	} static_default;

	// Converts from a const qualified ref/ptr to a non-const-qualified ref/ptr.
	// - Make sure the use is documented, this is very hacky behaviour!
	//
	template<typename T> static constexpr T& make_mutable( const T& x ) noexcept { return ( T& ) x; }
	template<typename T> static constexpr T* make_mutable( const T* x ) noexcept { return ( T* ) x; }

	// Converts from a non-const qualified ref/ptr to a const-qualified ref/ptr.
	//
	template<typename T> static constexpr std::add_const_t<T>& make_const( T& x ) noexcept { return x; }
	template<typename T> static constexpr std::add_const_t<T>* make_const( T* x ) noexcept { return x; }

	// Creates a copy of the given value.
	//
	template<typename T> __forceinline static constexpr T make_copy( const T& x ) { return x; }

	// Creates an uninitialized T.
	//
	template<typename T> __forceinline static T make_uninit()
	{
		char raw[ sizeof( T ) ];
		return std::move( *( T* ) &raw );
	}

	// Implement helpers for basic series creation.
	//
	namespace impl
	{
		template<typename Ti, typename T, Ti... I>
		static constexpr auto make_expanded_series( T&& f, std::integer_sequence<Ti, I...> )
		{
			return std::array{ f( I )... };
		}

		template<typename Ti, template<auto> typename Tr, typename T, Ti... I>
		static constexpr auto make_visitor_series( T&& f, std::integer_sequence<Ti, I...> )
		{
			return std::array{ f( type_tag<Tr<I>>{} )... };
		}
	};
	template<auto N, typename T>
	static constexpr auto make_expanded_series( T&& f )
	{
		return impl::make_expanded_series<decltype( N )>( std::forward<T>( f ), std::make_integer_sequence<decltype( N ), N>{} );
	}
	template<auto N, template<auto> typename Tr, typename T>
	static constexpr auto make_visitor_series( T&& f )
	{
		return impl::make_visitor_series<decltype( N ), Tr, T>( std::forward<T>( f ), std::make_integer_sequence<decltype( N ), N>{} );
	}
};