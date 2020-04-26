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
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <algorithm>
#include <memory>
#include <stdlib.h>
#include <optional>
#include "concept.hpp"
#include "..\io\asserts.hpp"

namespace vtil
{
	namespace impl
	{
		// Swaps the given container's allocator with [A].
		//
		template<typename T, typename A>
		struct swap_allocator { using type = void; };
		template<template<typename...> typename C, typename... T, typename A>
		struct swap_allocator<C<T...>, A> { using type = typename C<std::conditional_t<std::is_same_v<T, typename C<T...>::allocator_type>, A, T>...>; };

		template<typename T, typename A>
		using swap_allocator_t = typename swap_allocator<T, A>::type;

		// Determines traits of equal and not equal comparison for the type.
		//
		template<typename... D>
		struct is_eq_comparable : concept_base<is_eq_comparable, D...>
		{
			template<typename T> static auto f( T v ) -> decltype( v == v );
		};

		template<typename... D>
		struct is_neq_comparable : concept_base<is_neq_comparable, D...>
		{
			template<typename T> static auto f( T v ) -> decltype( v != v );
		};
	};

	// This allocator internally allocates a buffer of size [N]. The first 
	// allocations that can be allocated directly from this buffer will use 
	// the buffer and frees of those allocations will be ignored unless done 
	// so in order. Rest of the allocations will invoke the default allocator. 
	// It could be more efficient in terms of actually processing the deallocations 
	// but might as well use the already implemented heap in that case.
	//
	// - Note: Naively assumes allocation and deallocation sizes respect the type's 
	//         alignment requirements so do not rebind to another type.
	//
	template<typename T, size_t N, typename default_allocator = std::allocator<T>>
	struct stack_buffered_allocator : default_allocator
	{
		// Clamp the N value to [0x100, 0x1000].
		//
		static constexpr size_t max_allocation_size = std::clamp<size_t>( N, 0x100, 0x1000 );

		// Buffer aligned to match the alignment of T. 
		//
		__declspec( align( alignof( T ) ) ) uint8_t buffer[ max_allocation_size ];
		
		// Number of bytes we've allocated.
		//
		size_t size_of_allocations = 0;

		// Allocation routine.
		//
		T* allocate( size_t n, void* hint = 0 )
		{
			// If it can be allocated from the buffer:
			//
			if ( ( size_of_allocations + n ) <= max_allocation_size )
			{
				// Forward the iterator [n] bytes ahead, return the previous iterator.
				//
				T* ptr = ( T* ) &buffer[ size_of_allocations ];
				size_of_allocations += n;
				return ptr;
			}

			// Otherwise redirect to default allocator.
			//
			return default_allocator::allocate( n, hint );
		}

		// Deallocation routine.
		//
		void deallocate( T* ptr, size_t n )
		{
			// If deallocating from the buffer:
			//
			if ( ( void* ) std::begin( buffer ) <= ptr && ptr < ( void* ) std::end( buffer ) )
			{
				// If deallocating previous allocation, free buffer.
				//
				if ( buffer[ size_of_allocations - n ] == ( uint8_t* ) ptr )
					size_of_allocations -= n;
				
				// Return to the caller.
				//
				return;
			}

			// Otherwise redirect to default allocator.
			//
			default_allocator::deallocate( ptr, n );
		}
	};

	// Define generic stack-buffered container.
	//
	template<typename T, size_t N, bool do_reserve,
		typename allocator_t = stack_buffered_allocator<typename T::value_type, N * sizeof( typename T::value_type ), typename T::allocator_type>,
		typename container_t = impl::swap_allocator_t<T, allocator_t>>
	struct stack_buffered_container : public container_t
	{
		allocator_t stack_buffer = {};

		// Constructor forwards as is, ideally should be initially constructed
		// with no parameters to make sure the buffer is utilized as much as possible.
		//
		template<typename... T>
		stack_buffered_container( T&&... args ) : container_t( std::forward<T>( args )..., stack_buffer ) 
		{ 
			if constexpr( do_reserve )
				container_t::reserve( N ); 
		}
	};

	// Wrap basic string derivatives:
	// - Note: Strings might be unnecessary as the internal implementation already does SSO 
	//		   optimization but might be useful for large strings, so will define anyway.
	//
	template<size_t N = 512>
	using stack_string =                 stack_buffered_container<std::string, N, true>;
	template<size_t N = 512>
	using stack_wstring =                stack_buffered_container<std::wstring, N, true>;
	template<typename C, typename T = std::char_traits<C>, size_t N = 512>
	using basic_stack_string =           stack_buffered_container<std::basic_string<C, T>, N, true>;

	// Wrap vector:
	//
	template<typename T, size_t N = 16>
	using stack_vector =                 stack_buffered_container<std::vector<T>, N, true>;
	
	// Wrap set deriavtives:
	//
	template<typename T, typename P = std::less<T>, size_t N = 16>
	using stack_set =                    stack_buffered_container<std::set<T, P>, N, false>;
	template<typename T, typename H = std::hash<T>, size_t N = 16>
	using unordered_stack_set =          stack_buffered_container<std::unordered_set<T, H>, N, false>;

	// Wrap map deriavtives:
	//
	template<typename K, typename V, typename P = std::less<K>, size_t N = 16>
	using stack_map =                    stack_buffered_container<std::map<K, V, P>, N, false>;
	template<typename K, typename V, typename H = std::hash<K>, size_t N = 16>
	using unordered_stack_map =          stack_buffered_container<std::unordered_map<K, V, H>, N, false>;

	// Wrap multimap deriavtives:
	//
	template<typename K, typename V, typename P = std::less<K>, size_t N = 16>
	using stack_multimap =               stack_buffered_container<std::multimap<K, V, P>, N, false>;
	template<typename K, typename V, typename H = std::hash<K>, size_t N = 16>
	using unordered_stack_multimap =     stack_buffered_container<std::unordered_multimap<K, V, H>, N, false>;
};