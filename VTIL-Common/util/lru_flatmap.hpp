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
#include "type_helpers.hpp"
#include "detached_queue.hpp"
#include "flat_allocator.hpp"
#include "../io/logger.hpp"
#include "../math/bitwise.hpp"

namespace vtil
{
	namespace impl
	{
		static constexpr size_t primes[] = {
			53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, 98317, 
			196613, 393241, 786433, 1572869, 3145739, 6291469, 12582917, 25165843, 
			50331653, 100663319, 201326611, 402653189, 805306457, 1610612741
		};

		static constexpr size_t pick_prime( size_t object_count )
		{
			for ( size_t n : primes )
				if ( n > object_count )
					return n;
			return object_count;
		}
	};

	// Declare a flat hashmap.
	//
	template<typename K, typename V, typename hasher = std::hash<K>>
	struct lru_flatmap
	{
		// Declare bucket header.
		//
		struct bucket_header
		{
			size_t hash;
			bucket_header* low = nullptr;
			bucket_header* high = nullptr;
		};

		// Declare entry type.
		//
		struct entry_type
		{
			// Bucket header.
			//
			bucket_header bucket_entry;

			// LRU list and lock count.
			//
			entry_type* lru_prev;
			entry_type* lru_next;
			int64_t lock_count = 0;
			
			// Key and value.
			//
			std::pair<K, V> kv;
		};

		// Declare reference wrapper.
		//
		template<auto F = &entry_type::kv>
		struct reference_wrapper
		{
			entry_type* p = nullptr;

			reference_wrapper() {}
			reference_wrapper( entry_type* p ) : p( p ) { p->lock_count++; }
			template<auto F2> reference_wrapper( reference_wrapper<F2>&& o ) : p( std::exchange( o.p, nullptr ) ) {}
			template<auto F2> reference_wrapper& operator=( reference_wrapper<F2>&& o ) { std::swap( p, o.p ); return *this; }
			~reference_wrapper() { if ( p ) p->lock_count--; }

			auto* operator->() { return &(p->*F); }
			auto& operator*() { return p->*F; }
			const auto* operator->() const { return &(p->*F); }
			const auto& operator*()  const { return p->*F; }
			explicit operator bool() const { return p != nullptr; }
			operator entry_type*() { return p; }
		};

		// Entry allocator.
		//
		flat_allocator<entry_type> entry_allocator;

		// The hash buckets.
		//
		struct bucket_type : bucket_header
		{
			bucket_type() : bucket_header{ .hash = 1ull << 63 } {}
		};
		const size_t bucket_count;
		std::unique_ptr<bucket_type[]> buckets;

		// LRU list.
		//
		entry_type* lru_head = nullptr;
		entry_type* lru_tail = nullptr;
		
		// Constructor takes map configuration.
		//
		float prune_coefficient;
		lru_flatmap( size_t num_items, float prune_coefficient )
			: entry_allocator( num_items ), prune_coefficient( prune_coefficient ),
			  bucket_count( impl::pick_prime( num_items ) ), buckets{ new bucket_type[ bucket_count ]() } { }

		// No copy, default move.
		//
		lru_flatmap( lru_flatmap&& ) = default;
		lru_flatmap( const lru_flatmap& ) = delete;
		lru_flatmap& operator=( lru_flatmap&& ) = default;
		lru_flatmap& operator=( const lru_flatmap& ) = delete;

		// Reset the map.
		//
		void clear()
		{
			// Delete all items.
			//
			for ( auto it = lru_head; it; it = it->lru_next )
			{
				std::destroy_at( &it->kv );
				entry_allocator.deallocate( it );
			}
			lru_head = lru_tail = nullptr;

			// Reset buckets.
			//
			for ( size_t i = 0; i < bucket_count; i++ )
				new ( &buckets.get()[ i ] ) bucket_type();
		}

		// Finds the balanced node given the hash.
		//
		bucket_header* find_node( size_t hash )
		{
			// Find the balanced node.
			//
			bucket_header* it = &buckets.get()[ hash % bucket_count ];
			if ( it->hash > hash )
			{
				while ( it->low && it->low->hash >= hash )
					it = it->low;
			}
			else
			{
				while ( it->high && it->high->hash <= hash )
					it = it->high;
			}
			return it;
		}
		
		// Element insertation.
		//
		template<typename... Tx>
		reference_wrapper<> emplace( Tx&&... args )
		{
			// If we cannot allocate an entry, prune the list.
			//
			if ( entry_allocator.free_list.empty() )
				prune();

			// Allocate an entry.
			//
			entry_type* entry = entry_allocator.allocate();
			fassert( entry );
			new ( &entry->kv ) std::pair<const K, V>( std::forward<Tx>( args )... );

			// Find the balanced node for the item.
			//
			size_t hash = hasher{}( entry->kv.first );
			bucket_header* it = find_node( hash );

			// Link after it.
			//
			entry->bucket_entry.hash = hash;
			if( it->hash > hash )
			{
				entry->bucket_entry.low = it->low;
				entry->bucket_entry.high = it;
				it->low = &entry->bucket_entry;
				if ( entry->bucket_entry.low )
					entry->bucket_entry.low->high = &entry->bucket_entry;
			}
			else
			{

				entry->bucket_entry.low = it;
				entry->bucket_entry.high = it->high;
				it->high = &entry->bucket_entry;
				if ( entry->bucket_entry.high )
					entry->bucket_entry.high->low = &entry->bucket_entry;
			}

			// Link to LRU.
			//
			entry->lock_count = 0;
			if ( !lru_head )
			{
				entry->lru_prev = nullptr;
				entry->lru_next = nullptr;
				lru_head = lru_tail = entry;
			}
			else
			{
				entry->lru_prev = lru_tail;
				entry->lru_next = nullptr;
				lru_tail->lru_next = entry;
				lru_tail = entry;
			}

			// Return the entry.
			//
			return entry;
		}

		// Element lookup.
		//
		reference_wrapper<> operator[]( const K& key )
		{
			// Find the balanced node for the item.
			//
			size_t hash = hasher{}( key );
			bucket_header* it = find_node( hash );
			if ( it->hash == hash && ( it->low || it->high ) )
			{
				entry_type* entry = ( entry_type* ) it;
				return entry;
			}
			return {};
		};
		
		// Element deletion.
		//
		void erase( entry_type* entry )
		{
			fassert( !entry->lock_count );

			// Unlink from LRU list.
			//
			if ( entry->lru_next )
				entry->lru_next->lru_prev = entry->lru_prev;
			else
				lru_tail = entry->lru_prev;
			if ( entry->lru_prev )
				entry->lru_prev->lru_next = entry->lru_next;
			else
				lru_head = entry->lru_next;

			// Unlink from bucket.
			//
			if ( entry->bucket_entry.low )
				entry->bucket_entry.low->high = entry->bucket_entry.high;
			if ( entry->bucket_entry.high )
				entry->bucket_entry.high->low = entry->bucket_entry.low;

			// Deallocate the key/value pair and release the memory.
			//
			std::destroy_at( &entry->kv );
			entry_allocator.deallocate( entry );
		}
		void prune()
		{
			isize_t n = ( size_t ) ( entry_allocator.size * prune_coefficient );
			for ( auto it = lru_head; it && n != 0; )
			{
				auto next = it->lru_next;
				if ( !it->lock_count )
					erase( it ), n--;
				it = next;
			}
		}

		// Simple helpers to change the priority of an entry.
		//
		void prune_next( entry_type* entry )
		{
			// If the only entry or the head, return.
			//
			if ( lru_head == entry )
				return;

			// Unlink.
			//
			if ( lru_tail == entry )
			{
				lru_tail = entry->lru_prev;
				lru_tail->lru_next = nullptr;
			}
			else
			{
				entry->lru_next->lru_prev = entry->lru_prev;
				entry->lru_prev->lru_next = entry->lru_next;
			}

			// Relink as head.
			//
			entry->lru_prev = nullptr;
			entry->lru_next = lru_head;
			lru_head->lru_prev = entry;
			lru_head = entry;
		}
		void prune_last( entry_type* entry )
		{
			// If the only entry or the tail, return.
			//
			if ( lru_tail == entry )
				return;

			// Unlink.
			//
			if ( lru_head == entry )
			{
				lru_head = entry->lru_next;
				lru_head->lru_prev = nullptr;
			}
			else
			{
				entry->lru_next->lru_prev = entry->lru_prev;
				entry->lru_prev->lru_next = entry->lru_next;
			}

			// Relink as tail.
			//
			entry->lru_prev = lru_tail;
			entry->lru_next = nullptr;
			lru_tail->lru_next = entry;
			lru_tail = entry;
		}

		// Basic destructor.
		//
		~lru_flatmap()
		{
			// Delete all items.
			//
			if ( buckets )
			{
				for ( auto it = lru_head; it; it = it->lru_next )
					std::destroy_at( &it->kv );
			}
		}
	};
};