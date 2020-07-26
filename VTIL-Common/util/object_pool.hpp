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
#include <cstdlib>
#include <atomic>
#include <algorithm>
#include "detached_queue.hpp"
#include "thread_identifier.hpp"
#include "type_helpers.hpp"

// [Configuration]
// Determine the number of buckets and the rellocation buffer entries we allocate and reserve.
//
#ifndef VTIL_OBJECT_POOL_BUCKETS
	#define	VTIL_OBJECT_POOL_BUCKETS       36
	#define VTIL_OBJECT_POOL_INITIAL_SIZE  ( 1ull   * 1024 * 1024 )
	#define VTIL_OBJECT_POOL_GROWTH_CAP    ( 512ull * 1024 * 1024 )
	#define VTIL_OBJECT_POOL_GROWTH_FACTOR 2
#endif
namespace vtil
{
	// Object pools allow for fast singular type allocation based on plf::colony.
	//
	template <typename T>
	struct object_pool
	{
		// Forward declares and type exports.
		//
		using value_type = T;
		struct pool_instance;
		struct bucket_entry;

		// A single entry in the pool.
		//
		struct alignas( T ) object_entry
		{
			// Stores raw data.
			//
			uint8_t raw_data[ sizeof( T ) ];

			// Pointer to owning pool.
			//
			pool_instance* pool;

			// Whether object has to be destructed to be used again or not.
			//
			bool deferred_destruction = false;

			// Key for free queue.
			//
			detached_queue_key<object_entry> free_queue_key;

			// Decay into object pointer.
			//
			T* decay() { return ( T* ) &raw_data[ 0 ]; }
			const T* decay() const { return ( const T* ) make_mutable( this )->decay(); }

			// Resolve from object pointer.
			//
			static object_entry* resolve( const void* obj ) { return ptr_at<object_entry>( ( T* ) obj, -make_offset( &object_entry::raw_data ) ); }
		};

		// Base pool type.
		//
		struct pool_instance
		{
			// Key for the pool queue.
			//
			detached_queue_key<pool_instance> pool_queue_key;

			// Number of objects we store and the objects themselves.
			//
			size_t object_count;
			object_entry objects[ 1 /* N */ ];
		};

		// Bucket entry dedicating a pool list to each thread.
		//
		struct bucket_entry
		{
			// Atomic queue of free memory regions.
			//
			atomic_detached_queue<object_entry> free_queue;

			// Mutex protecting the pool list.
			//
			std::mutex pool_allocator_mutex;

			// Last of last pool in bytes, approximated.
			//
			size_t last_pool_size_raw = 0;
			
			// List of pools.
			//
			detached_queue<pool_instance> pools;
		};

		// Declare the pool allocator.
		//
		using pool_base_unit = std::aligned_storage<1, alignof( pool_instance )>;
		using pool_allocator = std::allocator<pool_base_unit>;

		// Atomic counter responsible of the grouping of threads => buckets.
		//
		inline static std::atomic<size_t> counter = { 0 };
		
		// Global list of buckets.
		//
		inline static bucket_entry buckets[ VTIL_OBJECT_POOL_BUCKETS ] = {};
		
		// Current bucket entry, decided at thread initialization.
		//
		inline static thread_local bucket_entry& local_bucket = buckets[ counter++ % VTIL_OBJECT_POOL_BUCKETS ];

		// Allocation and deallocation.
		//
		static T* allocate( bool deferred_destruction = false )
		{
			static_assert( sizeof( object_entry ) < VTIL_OBJECT_POOL_INITIAL_SIZE, "Objects cannot be larger than initial size." );

			// Fetch local bucket from TLS.
			//
			bucket_entry& bucket = local_bucket;

			// Enter pool allocation loop:
			//
			while ( true )
			{
				// Pop entry from free queue, if non null:.
				//
				if ( object_entry* entry = bucket.free_queue.pop_back( &object_entry::free_queue_key ) )
				{
					// If it's destruction was deferred, do so now.
					//
					if ( entry->deferred_destruction )
						std::destroy_at<T>( entry->decay() );

					// Return the entry.
					//
					entry->deferred_destruction = deferred_destruction;
					return entry->decay();
				}

				// Acquire pool allocator mutex.
				//
				std::lock_guard _gp{ bucket.pool_allocator_mutex };

				// If free queue is already filled, try again.
				//
				if ( !bucket.free_queue.empty() )
					continue;

				// Determine new pool's size (raw size is merely an approximation).
				//
				size_t new_pool_size_raw = bucket.last_pool_size_raw
					? std::min<size_t>( bucket.last_pool_size_raw * VTIL_OBJECT_POOL_GROWTH_FACTOR, VTIL_OBJECT_POOL_GROWTH_CAP )
					: VTIL_OBJECT_POOL_INITIAL_SIZE;
				bucket.last_pool_size_raw = new_pool_size_raw;
				size_t object_count = new_pool_size_raw / sizeof( object_entry );

				// Allocate the pool, initialize the header.
				//
				pool_instance* new_pool = ( pool_instance* ) pool_allocator{}.allocate(
					( sizeof( pool_instance ) + sizeof( object_entry ) * ( object_count - 1 ) + sizeof( pool_base_unit ) - 1 ) / sizeof( pool_base_unit )
				);
				new_pool->object_count = object_count;

				// We'll keep the first object to ourselves.
				//
				object_entry* return_value = &new_pool->objects[ 0 ];
				return_value->pool = new_pool;
				return_value->deferred_destruction = deferred_destruction;
				return_value->free_queue_key.active = false;

				// Initialize every other object, linking them internally so that 
				// we don't have to hold the free-list lock too long.
				//
				object_entry* tmp_prev = nullptr;
				for ( size_t i = 1; i < object_count; i++ )
				{
					new ( new_pool->objects + i ) object_entry{
						.pool = new_pool,
						.deferred_destruction = false,
						.free_queue_key = {
							.active = true,
							.prev = &new_pool->objects[ i - 1 ].free_queue_key,
							.next = &new_pool->objects[ i + 1 ].free_queue_key
						}
					};
				}
				auto* head = &new_pool->objects[ 1 ];
				auto* tail = &new_pool->objects[ object_count - 1 ];
				head->free_queue_key.prev = nullptr;
				tail->free_queue_key.next = nullptr;
				
				// Insert into pools list.
				//
				bucket.pools.emplace_back( &new_pool->pool_queue_key );

				// Lock the free queue and manually link.
				//
				std::lock_guard _gf{ bucket.free_queue };

				if ( bucket.free_queue.tail )
				{
					bucket.free_queue.tail->next = &head->free_queue_key;
					head->free_queue_key.prev = bucket.free_queue.tail;
					bucket.free_queue.tail = &tail->free_queue_key;
				}
				else
				{
					bucket.free_queue.head = &head->free_queue_key;
					bucket.free_queue.tail = &tail->free_queue_key;
				}
				bucket.free_queue.list_size += object_count - 1;

				// Return the allocated address.
				//
				return return_value->decay();
			}
		}
		static void deallocate( T* pointer, bool deferred_destruction = false )
		{
			// Fetch local bucket from TLS.
			//
			bucket_entry& bucket = local_bucket;

			// Resolve object entry, set deferred destruction and emplace it into the free queue.
			//
			object_entry* object_entry = object_entry::resolve( pointer );
			object_entry->deferred_destruction = deferred_destruction;
			bucket.free_queue.emplace_back( &object_entry->free_queue_key );

			/*
			// TODO: Perhaps deallocate if whole pool is not used?

			// Delete from bucket.
			//
			bucket->pools.erase( std::remove( bucket->pools.begin(), bucket->pools.end(), pool ), bucket->pools.end() );

			// Simply deallocate the pool.
			//
			allocator{}.deallocate(
				pool,
				( sizeof( pool_instance ) + sizeof( object_entry ) * ( pool->object_count - 1 ) ) / sizeof( base_unit )
			);
			*/
		}

		// Construct / deconsturct wrappers.
		//
		template<typename... Tx>
		__forceinline static T* construct( Tx&&... args ) { return new ( allocate( true ) ) T( std::forward<Tx>( args )... ); }
		__forceinline static void destruct( T* pointer ) { return deallocate( pointer, true ); }
	};
};