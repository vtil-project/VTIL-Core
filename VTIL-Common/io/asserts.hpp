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
#include <stdint.h>
#include <stdexcept>
#include "logger.hpp"
#include "../util/intrinsics.hpp"

namespace vtil
{
	// Aborts if the given condition is met.
	//
	__forceinline static constexpr void abort_if( bool condition, const char* string )
	{
		// If condition met:
		//
		if ( condition ) [[unlikely]]
		{
			// Throw exception if consteval, else invoke logger error.
			//
			if ( std::is_constant_evaluated() ) throw std::logic_error{ string };
			else                                logger::error( "Assertion failure, %s", string );
		}
	}

	// A helper to throw formatted strings.
	//
	template<typename... params>
	__forceinline static void fthrow [[noreturn]] ( const char* fmt, params&&... ps )
	{
		// Format error message.
		//
		throw std::runtime_error( format::str(
			fmt,
			format::fix_parameter<params>( std::forward<params>( ps ) )...
		) );
	}
};

// Declare main assert macro.
//
#define xassert__stringify(x) #x
#define xassert__istringify(x) xassert__stringify(x)
#define xassert(...) vtil::abort_if(!bool(__VA_ARGS__), xassert__stringify(__VA_ARGS__) " at " __FILE__ ":" xassert__istringify(__LINE__) )

// Declare assertions, dassert is debug mode only, fassert is demo mode only, _s helpers 
// have the same functionality but still evaluate the statement.
//
#if VASSERT_LEVEL >= 2
	#define dassert(...)     xassert( __VA_ARGS__ )
	#define dassert_s( ... ) xassert( __VA_ARGS__ )
	#define fassert(...)     xassert( __VA_ARGS__ )
	#define fassert_s( ... ) xassert( __VA_ARGS__ )
#elif VASSERT_LEVEL >= 1
	#define dassert(...)     
	#define dassert_s( ... ) ( __VA_ARGS__ )
	#define fassert(...)     xassert( __VA_ARGS__ )
	#define fassert_s( ... ) xassert( __VA_ARGS__ )
#else
	#define dassert(...)     
	#define dassert_s( ... ) ( __VA_ARGS__ )
	#define fassert(...)     
	#define fassert_s( ... ) ( __VA_ARGS__ )
#endif

// Declare validation macro, used for generic is_valid() declaration where you want 
// to abort execution at the specific point of failure if caller aborts upon finding
// and invalid instance, and returns false from it otherwise. Macro is needed since
// it is essentially "return if".
//
#define vvalidate(enforce_valid, ...) {       \
                if ( enforce_valid ) {        \
                    fassert( __VA_ARGS__ );   \
                } else if( !(__VA_ARGS__) ) { \
                    return false;             \
                }                             \
            }
#define cvalidate(...) vvalidate(force, __VA_ARGS__)