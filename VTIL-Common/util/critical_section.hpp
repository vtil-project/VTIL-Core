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

namespace vtil
{
	// Returns the thread identifier in a platform independent way,
	// used instead of std::thread::get_id() as conversion to an integer
	// requires std::hash...
	//
	using tid_t = size_t;
	tid_t get_thread_id();

	// Implements a structure that mimics the way Win32 CRITICAL_SECTION objects work.
	// As long as it's the same thread, this lock can be acquired multiple times.
	//
	// - Note that this object assumes thread identifier cannot change 
	//   if it is equivalent to the current thread identifier, which holds
	//   since owner having the same thread identifier implies it was locked 
	//   by a routine that directly or indirectly called the current one 
	//   and since user-mode has no "yes but..."s to this, such as interrupts,
	//   we can conclude that we don't need to checkin again and unroll on mismatch.
	//
	struct critical_section
	{
		// The mutex that we wrap around.
		//
		std::mutex mtx;

		// Number of times the mutex was acquired by this thread.
		//
		std::atomic<int32_t> lock_count = 0;

		// Identifier of the thread that currently owns this mutex.
		//
		std::atomic<tid_t> owner = 0;

		// Default constructor, copying or moving this object is not allowed.
		//
		critical_section() = default;
		critical_section( critical_section&& ) = delete;
		critical_section( const critical_section& ) = delete;
		critical_section& operator=( critical_section&& ) = delete;
		critical_section& operator=( const critical_section& ) = delete;

		// Tries locking the mutex, returns true on success and false on failure.
		//
		bool try_lock();

		// Continously attempts to lock the mutex until it succeeds, returns only
		// when the mutex is acquired.
		//
		void lock();

		// Unlocks the mutex with the assumption that caller currently owns it.
		//
		void unlock();
	};
};