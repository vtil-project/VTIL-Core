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
#include <mutex>
#include <atomic>
#include "colony.hpp"

// [Configuration]
// Determine the number of buckets we allocate.
//
#ifndef VTIL_OBJECT_POOL_BUCKETS
	#define	VTIL_OBJECT_POOL_BUCKETS 512
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
		using generic_iterator = typename  plf::colony<bool>::iterator;
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

		inline T* allocate( size_t count )
		{
			// Must not be used to allocate an array.
			//
			fassert( count == 1 );

			// Get current bucket.
			//
			colony_bucket* bucket = get_bucket();

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
		inline void deallocate( T* pointer, size_t count ) noexcept
		{
			// Must not be used to deallocate an array.
			//
			fassert( count == 1 );

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