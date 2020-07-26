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
		bool active = false;
		detached_queue_key* prev;
		detached_queue_key* next;

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

		// Controls the lock.
		//
		void lock() const
		{
			if constexpr ( atomic )
				while ( spinlock.test_and_set( std::memory_order_acquire ) )
					_mm_pause();
		}
		void unlock() const
		{
			if constexpr ( atomic )
				spinlock.clear( std::memory_order_release );
		}

		// Inserts the key into the list.
		//
		void emplace_front( key* k )
		{
			std::lock_guard _g( *this );

			k->prev = nullptr;
			k->next = head;
			k->active = true;
			if ( head ) head->prev = k;
			if ( !tail ) tail = k;
			head = k;
			list_size++;
		}

		// Inserts the key into the list.
		//
		void emplace_back( key* k )
		{
			std::lock_guard _g( *this );

			k->prev = tail;
			k->next = nullptr;
			k->active = true;
			if ( tail ) tail->next = k;
			if ( !head ) head = k;
			tail = k;
			list_size++;
		}

		// Erases the key from the list, if linked.
		//
		void erase( key* k, bool inherit_lock = false )
		{
			if ( !k->active ) return;

			if ( !inherit_lock ) lock();

			if ( head == k ) head = k->next;
			if ( tail == k ) tail = k->prev;
			if ( k->prev ) k->prev->next = k->next;
			if ( k->next ) k->next->prev = k->prev;
			k->prev = nullptr;
			k->next = nullptr;
			k->active = false;
			list_size--;

			if ( !inherit_lock ) unlock();
		}

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
				erase( entry, true );
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
				erase( entry, true );
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