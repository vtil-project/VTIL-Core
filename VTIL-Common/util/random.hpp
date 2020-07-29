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
#include <random>
#include <stdint.h>
#include <type_traits>
#include <array>
#include "type_helpers.hpp"

namespace vtil
{
	namespace impl
	{
		// Declare the constexpr random seed.
		//
		static constexpr uint64_t crandom_default_seed = ([]()
		{
			uint64_t value = 0xa0d82d3adc00b109;
			for ( char c : __TIME__ )
				value = ( value ^ c ) * 0x100000001B3;
			return value;
		} )();

		// Linear congruential generator using the constants from Numerical Recipes.
		//
		static constexpr uint64_t lce_64( uint64_t& value )
		{
			return ( value = 1664525 * value + 1013904223 );
		}

		// Declare a random engine state per thread.
		//
		static thread_local std::default_random_engine local_rng( std::random_device{}() );
	};

	// Generates a single random number.
	//
	template<typename T>
	static T make_random( T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max() )
	{
		return std::uniform_int_distribution<T>{ min, max }( impl::local_rng );
	}
	static constexpr uint64_t make_crandom( size_t offset = 0 )
	{
		uint64_t value = impl::crandom_default_seed;
		while ( offset-- != 0 ) impl::lce_64( value );
		return impl::lce_64( value );
	}

	// Generates an array of random numbers.
	//
	template<typename T, size_t... I>
	static std::array<T, sizeof...( I )> make_random_n( T min, T max, std::index_sequence<I...> )
	{
		return { ( I, make_random<T>( min ,max ) )... };
	}
	template<size_t... I>
	static constexpr std::array<uint64_t, sizeof...( I )> make_crandom_n( size_t offset, std::index_sequence<I...> )
	{
		uint64_t value = offset ? make_crandom( offset - 1 ) : impl::crandom_default_seed;
		return { impl::lce_64( ( I, value ) )... };
	}
	template<typename T, size_t N>
	static auto make_random_n( T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max() )
	{
		return make_random_n<T>( min, max, std::make_index_sequence<N>{} );
	}
	template<size_t N>
	static constexpr auto make_crandom_n( size_t offset = 0 )
	{
		return make_crandom_n( offset, std::make_index_sequence<N>{} );
	}

	// Picks a random item from the initializer list / argument pack.
	//
	template<typename T>
	static auto pick_random( std::initializer_list<T> list )
	{
		fassert( list.size() != 0 );
		return *( list.begin() + make_random<size_t>( 0, list.size() - 1 ) );
	}
	template<Iterable T>
	static decltype( auto ) pick_randomi( T&& source )
	{
		auto size = dynamic_size( source );
		fassert( size != 0 );
		return dynamic_get( source, make_random<size_t>( 0, size - 1 ) );
	}
	template<size_t offset = 0, typename... Tx>
	static constexpr auto pick_crandom( Tx&&... args )
	{
		return std::get<make_crandom( offset ) % sizeof...( args )>( std::tuple<Tx&&...>{ std::forward<Tx>( args )... } );
	}
	template<size_t offset = 0, Iterable T>
	static constexpr decltype( auto ) pick_crandomi( T& source )
	{
		auto size = dynamic_size( source );
		fassert( size != 0 );
		return dynamic_get( source, make_crandom( offset ) % size );
	}
};