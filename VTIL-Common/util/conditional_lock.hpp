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
#include <shared_mutex>

namespace vtil
{
	// This type behaves exactly the same as the original lock type, with the 
	// exception of constructing it empty if the condition bool is false.
	//
	template<typename lock_type, typename mutex_type>
	struct cnd_variant_lock : lock_type
	{
		// Default constructors
		//
		cnd_variant_lock() {}
		cnd_variant_lock( mutex_type& mtx ) : lock_type{ mtx } {}

		// Construct from mutex and condition.
		//
		cnd_variant_lock( mutex_type& mtx, bool condition )
		{
			// If condition is passed:
			//
			if ( condition )
			{
				// Create a secondary lock with the mutex being actually 
				// acquired and swap states with the current empty instance.
				//
				lock_type lock{ mtx };
				this->swap( lock );
			}
		}
	};

	// Declare shortcuts for unique_lock, shared_lock and lock_guard and their deduction guides.
	//
	template<typename T>
	struct cnd_unique_lock : cnd_variant_lock<std::unique_lock<T>, T> { using cnd_variant_lock<std::unique_lock<T>, T>::cnd_variant_lock; };
	template<typename T> 
	cnd_unique_lock( T&, bool )->cnd_unique_lock<T>;

	template<typename T>
	struct cnd_shared_lock : cnd_variant_lock<std::shared_lock<T>, T> { using cnd_variant_lock<std::shared_lock<T>, T>::cnd_variant_lock; };
	template<typename T> 
	cnd_shared_lock( T&, bool )->cnd_shared_lock<T>;

	template<typename T>
	struct cnd_lock_guard  : cnd_variant_lock<std::lock_guard<T>,  T> { using cnd_variant_lock<std::lock_guard<T>,  T>::cnd_variant_lock; };
	template<typename T> 
	cnd_lock_guard( T&, bool )->cnd_lock_guard<T>;
};