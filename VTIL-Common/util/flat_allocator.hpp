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
#include <memory>
#include "detached_queue.hpp"

namespace vtil
{
	namespace impl
	{
		template<typename T>
		union no_ctor_dtor
		{
			T typed;
			char raw = 0;
			no_ctor_dtor() {}
			~no_ctor_dtor() {}
		};

		struct no_destruct
		{ 
			template<typename T> 
			void operator()( T* x ) { free( ( void* ) x ); } 
		};

		template<typename T>
		using unique_mem = std::unique_ptr<T, no_destruct>;
	};

	// Declare a flat allocator, one dynamic, one fixed.
	//
	template<typename T>
	struct flat_allocator
	{
		struct entry_type
		{
			impl::no_ctor_dtor<T> value;
			detached_queue_key<entry_type> free_key;
		};

		// Number of entries we've comitted to and the free list.
		//
		size_t comitted = 0;
		detached_queue<entry_type> free_list = {};

		// Raw data.
		//
		size_t size;
		impl::unique_mem<entry_type[]> data;

		// Construct by entry count, no copy, default move.
		//
		flat_allocator( size_t n )
			: size( n ), data{ ( entry_type* ) malloc( sizeof( entry_type ) * n ), {} } {}
		flat_allocator( flat_allocator&& ) = default;
		flat_allocator( const flat_allocator& ) = delete;
		flat_allocator& operator=( flat_allocator&& ) = default;
		flat_allocator& operator=( const flat_allocator& ) = delete;

		// Basic allocation / deallocation interface.
		//
		T* allocate()
		{
			if ( comitted < size )
				return &data.get()[ comitted++ ].value.typed;
			if ( entry_type* e = free_list.pop_front( &entry_type::free_key ) )
				return &e->value.typed;
			return nullptr;
		}
		void deallocate( T* p )
		{
			entry_type* entry = ( entry_type* ) p;
			free_list.emplace_front( &entry->free_key );
		}

		// Returns true if further memory cannot be allocated using this allocator.
		//
		bool empty() const
		{
			return free_list.empty() && comitted >= size;
		}
	};

	template<typename T, size_t N>
	struct fixed_flat_allocator
	{
		struct entry_type
		{
			impl::no_ctor_dtor<T> value;
			detached_queue_key<entry_type> free_key;
		};

		// Number of entries we've comitted to and the free list.
		//
		size_t comitted = 0;
		detached_queue<entry_type> free_list = {};

		// Raw data.
		//
		static constexpr size_t size = N;
		entry_type data[ N ];

		// Default construct, no copy, no move.
		//
		fixed_flat_allocator(){}
		fixed_flat_allocator( fixed_flat_allocator&& ) = delete;
		fixed_flat_allocator( const fixed_flat_allocator& ) = delete;
		fixed_flat_allocator& operator=( fixed_flat_allocator&& ) = delete;
		fixed_flat_allocator& operator=( const fixed_flat_allocator& ) = delete;

		// Basic allocation / deallocation interface.
		//
		T* allocate()
		{
			if ( comitted < size )
				return &data[ comitted++ ].value.typed;
			if ( entry_type* e = free_list.pop_front( &entry_type::free_key ) )
				return &e->value.typed;
			return nullptr;
		}

		void deallocate( T* p )
		{
			entry_type* entry = ( entry_type* ) p;
			free_list.emplace_front( &entry->free_key );
		}
	};
};