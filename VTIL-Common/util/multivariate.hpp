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
#include <map>
#include <mutex>
#include <shared_mutex>
#include "variant.hpp"
#include "lt_typeid.hpp"
#include "type_helpers.hpp"
#include "relaxed_atomics.hpp"

namespace vtil
{
	template<typename C, typename T>
	concept ContextSynchronizable = requires( T v, C * p ) { p = &v.context; v.epoch; };

	// Synchronized context with an update callback that gets invoked if the previous value was outdated.
	//
	struct synchronized_context_tag {};
	template<typename owner>
	struct synchronized_context : synchronized_context_tag
	{
		// Lock for the update mechanism.
		//
		relaxed<std::mutex> update_lock;

		// Timestamp of the last update.
		//
		using stamp_t = decltype( owner::epoch );
		mutable relaxed_atomic<stamp_t> prev_epoch = {};

		// Pointer to the last owner.
		//
		mutable relaxed_atomic<const owner*> prev_owner = nullptr;

		// Implemented by parent, should update the context.
		//
		virtual void update( const owner* ) = 0;

		// Checks if the current context is updated for the given owner.
		//
		bool is_updated( const owner* p ) const
		{
			return p == prev_owner && p->epoch == prev_epoch;
		}

		// Returns a self-reference after making sure context is updated.
		//
		void update_if( const owner* p )
		{
			// If context is not updated:
			//
			if ( !is_updated( p ) )
			{
				// Acquire lock, if still not updated, invoke ::update and change the epoch&owner.
				//
				std::lock_guard _g( update_lock );
				if ( !is_updated( p ) )
				{
					update( p );
					prev_owner = p; 
					prev_epoch = p->epoch;
				}
			}
		}

		// Marks the context dirty.
		//
		void mark_dirty() const
		{
			prev_owner = nullptr;
		}
	};

	// Multivariates store multiple types in a non-template type, mainly to be used by
	// optimizers to store arbitrary per-block / per-instruction data at the respective 
	// structures directly.
	//
	template<typename owner>
	struct multivariate
	{
		mutable relaxed<std::shared_mutex> mtx;
		mutable std::unordered_map<size_t, variant> database;

		// Default copy/move/construct.
		//
		multivariate() = default;
		multivariate( const multivariate& o ) = default;
		multivariate( multivariate&& o ) = default;
		multivariate& operator=( const multivariate& o ) = default;
		multivariate& operator=( multivariate&& o ) = default;

		// Purges the object of the given type from the store.
		//
		template<typename T = void>
		void purge() const
		{
			std::unique_lock _g{ mtx };
			if constexpr ( std::is_void_v<T> )
				database.clear();
			else
				database.erase( lt_typeid_v<T> );
		}

		// Checks if we have the type in the store.
		//
		template<typename T>
		bool has() const
		{
			std::shared_lock _g{ mtx };
			return database.contains( lt_typeid_v<T> );
		}

		// Getter of the types.
		//
		template<typename T>
		T& get_raw() const
		{
			// Acquire shared lock and search for the value in the database:
			//
			T* value;
			mtx.lock_shared();
			auto it = database.find( lt_typeid_v<T> );

			// If value does not exist:
			//
			if ( it == database.end() )
			{
				// Upgrade to a unique lock, emplace a new value and unlock.
				//
				mtx.unlock_shared();
				mtx.lock();
				auto [it, inserted] = database.emplace( lt_typeid_v<T>, make_default<T>() );
				value = &it->second.template get<T>();
				mtx.unlock();
			}
			else
			{
				// Get a reference and unlock.
				//
				value = &it->second.template get<T>();
				mtx.unlock_shared();
			}
			return *value;
		}
		template<typename T>
		T& get() const
		{
			// If synchronized:
			//
			T& ref = get_raw<T>();
			if constexpr ( std::is_base_of_v<synchronized_context_tag, T> )
			{
				// Assert synchronizable validity.
				//
				static_assert( std::is_base_of_v<synchronized_context<owner>, T> 
							   && ContextSynchronizable<multivariate<owner>, owner>, "Invalid context-synchronizable." );

				// Updated context if required.
				//
				ref.update_if( ptr_at<owner>( this, -make_offset( &owner::context ) ) );
			}
			return ref;
		}

		// Allows for convinient use of the type in the format of:
		// - block_cache& cache = multivariate;
		//
		template<typename T>
		operator T&() const { return get<std::remove_const_t<T>>(); }
	};
};