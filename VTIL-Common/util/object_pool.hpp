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
#include <mutex>
#include <atomic>
#include "../ext/colony.hpp"
#include "../util/bitmap.hpp"
#include "thread_identifier.hpp"

// [Configuration]
// Determine the number of buckets and the rellocation buffer entries we allocate and reserve.
//
#ifndef VTIL_OBJECT_POOL_BUCKETS
	#define	VTIL_OBJECT_POOL_BUCKETS         512
	#define VTIL_OBJECT_POOL_REALLOC_BUFFER  1024
	#define VTIL_OBJECT_POOL_REALLOC_RESERVE 512
#endif
namespace vtil
{
	// Object pools allow for fast singular type allocation based on plf::colony.
	//
	template <typename T>
	struct object_pool
	{
		using value_type = T;

		// Define a type-less iterator to store in the value entry.
		//
		using generic_iterator = typename plf::colony<bool>::iterator;
		struct object_entry
		{
			void* bucket;
			generic_iterator iterator;
			uint8_t raw_data[ sizeof( T ) ];

			static object_entry* entry_of( void* obj )
			{
				uint64_t obj_adr = ( uint64_t ) obj - ( uint64_t ) ( &( ( object_entry* )nullptr )->raw_data );
				return ( object_entry* ) obj_adr;
			}
		};

		// Define the typed iterator to actually use.
		//
		using type_iterator = typename plf::colony<object_entry>::iterator;
		static_assert( sizeof( type_iterator ) == sizeof( generic_iterator ), "Iterator sizes are not matching." );

		// Define a colony wrapped around a mutex.
		//
		struct colony_bucket
		{
			plf::colony<object_entry> colony;
			std::mutex mtx;
		};

		// Gets the current colony assigned to the thread.
		//
		static colony_bucket* get_bucket()
		{
			static colony_bucket buckets[ VTIL_OBJECT_POOL_BUCKETS ] = {};
			return &buckets[ get_thread_id() % VTIL_OBJECT_POOL_BUCKETS ];
		}

		// Define a simple buffer used for fast "reallocation".
		//
		struct reallocation_buffer
		{
			bitmap<VTIL_OBJECT_POOL_REALLOC_BUFFER> state = {};
			T* entries[ VTIL_OBJECT_POOL_REALLOC_BUFFER ] = {};

			// Pushes the given pointer to the buffer.
			//
			bool push( T* p )
			{
				size_t n = state.find( false );
				if ( n == math::bit_npos ) return false;
				state.set( n, true );
				entries[ n ] = p;
				return true;
			}

			// Tries to pop an entry from the buffer, returns nullptr on failure.
			//
			T* pop()
			{
				size_t n = state.find( true );
				if ( n == math::bit_npos ) return nullptr;
				state.set( n, false );
				return std::exchange( entries[ n ], nullptr );
			}

			// Deallocate any leftovers upon destruction.
			//
			~reallocation_buffer()
			{
				auto entry_it = entries;
				for ( auto it = std::begin( state.blocks ); it != std::end( state.blocks ); it++, entry_it += 64 )
					for ( size_t i = 0; i < 64; i++, *it >>= 1 )
						if( *it & 1 )
							object_pool<T>{}.deallocate( entry_it[ i ] );
			}
		};
		inline static thread_local reallocation_buffer buffer = {};

		inline T* allocate( size_t count = 1 )
		{
			// Must not be used to allocate an array.
			//
			fassert( count == 1 );

			// Try the fast path where possible.
			//
			if ( auto p = buffer.pop() )
				return p;

			// Get current bucket.
			//
			colony_bucket* bucket = get_bucket();

			// If buffer is empty, populate it.
			//
			if ( buffer.state.find( true ) == math::bit_npos )
			{
				static constexpr size_t reserved_count = VTIL_OBJECT_POOL_REALLOC_RESERVE & ~7;

				// Lock the mutex.
				//
				std::lock_guard _g{ bucket->mtx };

				// Insert N reserved entries and insert them.
				//
				for ( size_t n = 0; n < reserved_count; n++ )
				{
					type_iterator it = bucket->colony.emplace();
					it->bucket = bucket;
					it->iterator = ( generic_iterator& ) it;
					buffer.entries[ n ] = ( T* ) it->raw_data;
				}
				memset( buffer.state.blocks, 0xFF, reserved_count / 8 );

				// Allocate an additional entry and return it.
				//
				type_iterator it = bucket->colony.emplace();
				it->bucket = bucket;
				it->iterator = ( generic_iterator& ) it;
				return ( T* ) it->raw_data;
			}

			// Lock the mutex, emplace an empty object and unlock.
			//
			bucket->mtx.lock();
			type_iterator it = bucket->colony.emplace();
			bucket->mtx.unlock();

			// Insert bucket and iterator information into the bucket entry and return raw data pointer as is.
			//
			it->bucket = bucket;
			it->iterator = ( generic_iterator& ) it;
			return ( T* ) it->raw_data;
		}

		inline void deallocate( T* pointer, size_t count = 1 ) noexcept
		{
			// Must not be used to deallocate an array.
			//
			fassert( count == 1 );

			// Try the fast path where possible.
			//
			if ( buffer.push( pointer ) )
				return;

			// Get the object header from the pointer.
			//
			object_entry* entry = object_entry::entry_of( pointer );
			colony_bucket* bucket = ( colony_bucket* ) entry->bucket;

			// Lock the mutex and erase from the colony.
			//
			bucket->mtx.lock();
			bucket->colony.erase( ( type_iterator& ) entry->iterator );
			bucket->mtx.unlock();
		}

		// Default construction, conversion is no-op.
		//
		object_pool() = default;
		template <typename T2>
		constexpr object_pool( const object_pool<T2>& ) noexcept {}

		// Different types are never equal.
		//
		template <typename T2> constexpr bool operator==( const object_pool<T2>& ) { return false; }
		template <typename T2> constexpr bool operator!=( const object_pool<T2>& ) { return true; }
	};
};