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
#include "../io/asserts.hpp"

namespace vtil
{
	namespace impl
	{
		// Swaps the given container's allocator with [A].
		//
		template<typename T, typename A>
		struct swap_allocator { using type = void; };
		template<template<typename...> typename C, typename... T, typename A>
		struct swap_allocator<C<T...>, A> { using type = C<typename std::conditional_t<std::is_same_v<T, typename C<T...>::allocator_type>, A, T>...>; };

		template<typename T, typename A>
		using swap_allocator_t = typename swap_allocator<T, A>::type;
	};


	// Stack buffer state with iterators enforcing equivalent alignment for any type.
	//
	template<typename T = uint8_t, typename real_type = T>
	struct stack_buffer_state
	{
		// Align [T] as if it was the original type of the buffer.
		//
		static constexpr size_t alignment_mask = alignof( real_type ) - 1;
		struct alignas( real_type ) realigned_type { T value; };

		// Declare 3-pointer iterators based on this type.
		//
		realigned_type* base;
		realigned_type* limit;
		realigned_type* it;

		// Default constructor.
		//
		stack_buffer_state() = default;

		// Construct state from any Tx(&)[N].
		//
		template<typename buffer_type>
		stack_buffer_state( buffer_type& buffer )
		{
			// Calculate the beginning of the aligned array, and set base, limit and it based on it.
			//
			uint64_t mem_begin = ( uint64_t( std::begin( buffer ) ) + alignment_mask ) & ~alignment_mask;
			base = it = ( realigned_type* ) mem_begin;
			limit = ( realigned_type* ) std::end( buffer );
		}
	};

	// This allocator is constructed from a stack buffer state. The first 
	// allocations that can be allocated directly from this buffer will use 
	// the buffer and frees of those allocations will be ignored unless done 
	// so in order. Rest of the allocations will invoke the default allocator. 
	// It could be more efficient in terms of actually processing the deallocations 
	// but might as well use the already implemented heap in that case.
	//
	template<typename T, typename real_type = T>
	struct stack_buffered_allocator
	{
		// Allocator traits.
		//
		using value_type =         T;
		using pointer =            T*;
		using const_pointer =      const T*;
		using void_pointer =       void*;
		using const_void_pointer = const void*;
		using size_type =          size_t;
		using difference_type =    int64_t;
		using is_always_equal =    std::false_type;

		template<typename U>
		struct rebind { using other = stack_buffered_allocator<U, T>; };

		// State of the original buffer.
		//
		stack_buffer_state<T, real_type>* state;

		// Construct from buffer state.
		//
		stack_buffered_allocator( stack_buffer_state<>* state ) 
			: state( ( stack_buffer_state<T, real_type>* )state ) {}

		// Construct from any buffered allocator of same [real_type].
		//
		template <typename T2>
		stack_buffered_allocator( const stack_buffered_allocator<T2, real_type>& o ) 
			: state( ( stack_buffer_state<T, real_type>* ) o.state ) {}
		//
		template <typename T2>
		stack_buffered_allocator( stack_buffered_allocator<T2, real_type>&& o ) 
			: state( ( stack_buffer_state<T, real_type>* ) o.state ) {}

		// Allocators are only equivalent if the internal state references
		// the same stack buffer.
		//
		template<typename T2>
		bool operator==( const stack_buffered_allocator<T2, real_type>& o ) const 
		{ 
			return ( void* ) state == ( void* ) o.state; 
		}

		// Allocation routine.
		//
		T* allocate( size_t n, void* hint = 0 )
		{
			// If it can be allocated from the buffer:
			//
			if ( ( state->it + n ) <= state->limit )
			{
				// Forward the iterator ahead [n] times, return the original iterator.
				//
				T* ptr = &state->it->value;
				state->it += n;
				return ptr;
			}

			// Otherwise redirect to default allocator.
			//
			std::allocator<T> default_allocator;
			return std::allocator_traits<std::allocator<T>>::allocate( default_allocator, n, hint );
		}

		// Deallocation routine.
		//
		void deallocate( T* ptr, size_t n )
		{
			// If deallocating from the buffer:
			//
			if ( &state->base->value <= ptr && ptr < &state->limit->value )
			{
				// If deallocating previous allocation, free buffer.
				//
				if ( &( state->it - n )->value == ptr )
					state->it -= n;
				
				// Return to the caller.
				//
				return;
			}

			// Otherwise redirect to default allocator.
			//
			std::allocator<T> default_allocator;
			return std::allocator_traits<std::allocator<T>>::deallocate( default_allocator, ptr, n );
		}
	};

	// Define generic stack-buffered container.
	//
	template<typename T, size_t N, bool do_reserve,
		typename allocator_t = stack_buffered_allocator<typename T::value_type>,
		typename container_t = impl::swap_allocator_t<T, allocator_t>>
	struct stack_buffered_container : public container_t
	{
		// Append 0x20 bytes for _DEBUG binaries to compensate for std::_Container_proxy;
		//
		static constexpr size_t align_mask = alignof( T ) - 1;
#ifdef _DEBUG
		static constexpr size_t buffer_size = N * sizeof( typename T::value_type ) + ( 0x20 + sizeof( T ) + align_mask ) * 2;
#else
		static constexpr size_t buffer_size = N * sizeof( typename T::value_type );
#endif

		// Buffer aligned to match the alignment of T. 
		//
		uint8_t buffer[ buffer_size + align_mask ];
		stack_buffer_state<> state;

		// Constructor forwards as is, ideally should be initially constructed
		// with no parameters to make sure the buffer is utilized as much as possible.
		//
		template<typename... Tx>
		stack_buffered_container( Tx&&... args )
			: container_t( std::forward<Tx>( args )..., allocator_t{ &( state = buffer, state ) } )
		{ 
			if constexpr( do_reserve )
				container_t::reserve( N ); 
		}

		// Disallow copy.
		//
		stack_buffered_container( const stack_buffered_container& ) = delete;
		stack_buffered_container& operator=( const stack_buffered_container& ) = delete;

		// Decay to original type via copy.
		//
		container_t decay() const { return { container_t::begin(), container_t::end() }; }
		operator container_t() const { return decay(); }
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
	
	// Wrap set derivatives:
	//
	template<typename T, typename P = std::less<T>, size_t N = 16>
	using stack_set =                    stack_buffered_container<std::set<T, P>, N, false>;
	template<typename T, typename H = std::hash<T>, size_t N = 16>
	using unordered_stack_set =          stack_buffered_container<std::unordered_set<T, H>, N, false>;

	// Wrap map derivatives:
	//
	template<typename K, typename V, typename P = std::less<K>, size_t N = 16>
	using stack_map =                    stack_buffered_container<std::map<K, V, P>, N, false>;
	template<typename K, typename V, typename H = std::hash<K>, size_t N = 16>
	using unordered_stack_map =          stack_buffered_container<std::unordered_map<K, V, H>, N, false>;

	// Wrap multimap derivatives:
	//
	template<typename K, typename V, typename P = std::less<K>, size_t N = 16>
	using stack_multimap =               stack_buffered_container<std::multimap<K, V, P>, N, false>;
	template<typename K, typename V, typename H = std::hash<K>, size_t N = 16>
	using unordered_stack_multimap =     stack_buffered_container<std::unordered_multimap<K, V, H>, N, false>;
};
