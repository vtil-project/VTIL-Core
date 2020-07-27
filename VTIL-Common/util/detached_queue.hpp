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
#include <atomic>
#include <mutex>
#include "intrinsics.hpp"
#include "type_helpers.hpp"

namespace vtil
{
	// Detached key.
	//
	template<typename T>
	struct detached_queue_key
	{
		detached_queue_key* prev = nullptr;
		detached_queue_key* next = nullptr;

		T* get( member_reference_t<T, detached_queue_key> ref ) { return ptr_at<T>( this, -make_offset( ref ) ); }
		const T* get( member_reference_t<T, detached_queue_key> ref ) const { return make_mutable( this )->get( std::move( ref ) ); }
	};

	// Detached in-place queue for tracking already allocated objects 
	// in a different order with no allocations.
	//
	template<typename T, bool atomic>
	struct base_detached_queue
	{
		// Detached key.
		//
		using key = detached_queue_key<T>;

		// Spinlock protecting the list.
		//
		mutable std::atomic_flag spinlock = ATOMIC_FLAG_INIT;

		// Head, tail and size tracking the list.
		//
		key* head = nullptr;
		key* tail = nullptr;
		size_t list_size = 0;

		// Size getter, no locks because if caller doesn't hold the
		// lock while processing this information it doesn't make 
		// sense eitherway.
		//
		bool empty() const  
		{ 
			return list_size == 0;
		}
		size_t size() const 
		{ 
			return list_size;
		}

		// Converts into type with no locks.
		//
		auto& nolock() { return ( base_detached_queue<T, false>& ) *this; }

		// Controls the lock.
		//
		void lock() const
		{
			if constexpr ( !atomic )
				return;

			while ( spinlock.test_and_set( std::memory_order_acquire ) )
				_mm_pause();
		}
		void unlock() const
		{
			if constexpr ( !atomic )
				return;
			
			spinlock.clear( std::memory_order_release );
		}

		// Inserts the entire queue into the list.
		//
		void emplace_front( base_detached_queue<T, false>& queue )
		{
			if ( queue.empty() ) return;

			std::lock_guard _g( *this );

			if ( head )
			{
				head->prev = queue.tail;
				queue.tail->next = tail;
				head = queue.head;
			}
			else
			{
				head = queue.head;
				tail = queue.tail;
			}
			list_size += queue.list_size;
			queue.reset();
		}
		void emplace_back( base_detached_queue<T, false>& queue )
		{
			if ( queue.empty() ) return;

			std::lock_guard _g( *this );

			if ( tail )
			{
				tail->next = queue.head;
				queue.head->prev = tail;
				tail = queue.tail;
			}
			else
			{
				head = queue.head;
				tail = queue.tail;
			}
			list_size += queue.list_size;
			queue.reset();
		}

		// Inserts the key into the list.
		//
		void emplace_front( key* k )
		{
			std::lock_guard _g( *this );

			k->prev = nullptr;
			k->next = head;
			if ( head ) head->prev = k;
			if ( !tail ) tail = k;
			head = k;
			list_size++;
		}
		void emplace_back( key* k )
		{
			std::lock_guard _g( *this );

			k->prev = tail;
			k->next = nullptr;
			if ( tail ) tail->next = k;
			if ( !head ) head = k;
			tail = k;
			list_size++;
		}

		// Erases the key from the list.
		//
		void erase( key* k )
		{
			std::lock_guard _g( *this );

			if ( head == k ) head = k->next;
			else if ( k->prev ) k->prev->next = k->next;

			if ( tail == k ) tail = k->prev;
			else if ( k->next ) k->next->prev = k->prev;

			k->prev = nullptr;
			k->next = nullptr;

			list_size--;
		}
		void erase_if( key* k ) { if ( validate( k ) ) erase( k ); }

		// Checks if the given key is a valid entry to this list.
		//
		bool validate( key* k ) const { return k->prev || k->next || head == k || tail == k; }

		// Resets the list.
		//
		void reset()
		{
			std::lock_guard _g( *this );

			head = nullptr;
			tail = nullptr;
			list_size = 0;
		}

		// Peek front / back, no locks, same reason as ::size.
		//
		T* front( member_reference_t<T, key> ref )
		{
			if ( key* entry = head )
				return entry->get( std::move( ref ) );
			return nullptr;
		}
		T* back( member_reference_t<T, key> ref )
		{
			if ( key* entry = head )
				return entry->get( std::move( ref ) );
			return nullptr;
		}
		
		// Pop front / back.
		//
		T* pop_front( member_reference_t<T, key> ref )
		{
			std::lock_guard _g( *this );

			if ( key* entry = head )
			{
				T* value = entry->get( std::move( ref ) );
				nolock().erase( entry );
				return value;
			}
			return nullptr;
		}
		T* pop_back( member_reference_t<T, key> ref )
		{
			std::lock_guard _g( *this );

			if ( key* entry = tail )
			{
				T* value = entry->get( std::move( ref ) );
				nolock().erase( entry );
				return value;
			}
			return nullptr;
		}
	};

	// Declare aliases using base class.
	//
	template<typename T> using detached_queue =        base_detached_queue<T, false>;
	template<typename T> using atomic_detached_queue = base_detached_queue<T, true>;
};