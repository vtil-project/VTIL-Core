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
#include "critical_section.hpp"

#if _WIN64
	#include <intrin.h>
#else
	#include <unistd.h>
	#include <sys/syscall.h>
#endif
#include "../io/asserts.hpp"

namespace vtil
{
	// Returns the thread identifier in a platform independent way,
	// used instead of std::thread::get_id() as conversion to an integer
	// requires std::hash...
	//
	tid_t get_thread_id()
	{
#if _WIN64
		static_assert( sizeof( tid_t ) == 8, "Thread identifier must be defined as a quadword." );
		return __readgsqword( 0x48 );
#else
		return ( tid_t ) syscall( SYS_gettid );
#endif
	}

	// Tries locking the mutex, returns true on success and false on failure.
	//
	bool critical_section::try_lock()
	{
		// If we could not acquire the mutex ownership:
		//
		if ( !mtx.try_lock() )
		{
			// If thread identifier does not match, report failure.
			//
			if ( owner.load() != get_thread_id() )
				return false;

			// Increment lock count.
			//
			lock_count++;
			return true;
		}

		// This thread now owns this mutex, report success.
		//
		owner.store( get_thread_id() );
		return true;
	}

	// Continously attempts to lock the mutex until it succeeds, returns only
	// when the mutex is acquired.
	//
	void critical_section::lock()
	{
		// If we could not acquire the mutex ownership:
		//
		if ( !mtx.try_lock() )
		{
			// If thread identifier matches, increment counter and return.
			//
			if ( owner.load() == get_thread_id() )
			{
				lock_count++;
				return;
			}

			// Spin until we acquire the mutex.
			//
			mtx.lock();
		}

		// Increment lock count and declare ownership.
		//
		fassert( lock_count++ == 0 );
		owner.store( get_thread_id() );
	}

	// Unlocks the mutex with the assumption that caller currently owns it.
	//
	void critical_section::unlock()
	{
		// Validate sanity.
		//
		fassert( owner.load() == get_thread_id() );

		// If lock count reached zero:
		//
		if ( --lock_count == 0 )
		{
			// Zero-out the owning thread-id and unlock the mutex.
			//
			owner.store( 0 );
			mtx.unlock();
		}
	}
};
