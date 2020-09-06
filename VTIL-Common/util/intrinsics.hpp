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
#include <type_traits>

#ifndef __has_builtin
	#define __has_builtin(x) 0
#endif

// Determine RTTI support.
//
#if defined(_CPPRTTI)
	#define HAS_RTTI	_CPPRTTI
#elif defined(__GXX_RTTI)
	#define HAS_RTTI	__GXX_RTTI
#elif defined(__has_feature)
	#define HAS_RTTI	__has_feature(cxx_rtti)
#else
	#define HAS_RTTI	0
#endif

// Determine bitcast support.
//
#if (defined(_MSC_VER) && _MSC_VER >= 1926)
	#define HAS_BIT_CAST 1
#else
	#define HAS_BIT_CAST __has_builtin(__builtin_bit_cast)
#endif

#ifdef _MSC_VER
    #include <intrin.h>
    #define unreachable() __assume(0)
    #define FUNCTION_NAME __FUNCSIG__

    // Declare rotlq | rotrq
    //
    __forceinline static constexpr uint64_t rotlq( uint64_t value, int count )
    {
        if ( !std::is_constant_evaluated() )
            return _rotl64( value, count );
        count %= 64;
        return ( value << count ) | ( value >> ( 64 - count ) );
    }
    __forceinline static constexpr uint64_t rotrq( uint64_t value, int count )
    {
        if ( !std::is_constant_evaluated() )
            return _rotr64( value, count );
        count %= 64;
        return ( value >> count ) | ( value << ( 64 - count ) );
    }

#else
    #if defined(__aarch64__)
        #define _mm_pause() asm volatile ("yield")
    #elif defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
        #include <emmintrin.h>
    #else
        #define _mm_pause()
    #endif

    #define unreachable() __builtin_unreachable()
    #define __forceinline __attribute__((always_inline))
    #define _AddressOfReturnAddress() ((void*)__builtin_frame_address(0))
    #define FUNCTION_NAME __PRETTY_FUNCTION__


    // Declare rotlq | rotrq
    //
    __forceinline static constexpr uint64_t rotlq( uint64_t value, int count )
    {
        if ( std::is_constant_evaluated() )
            count %= 64;
        return ( value << count ) | ( value >> ( 64 - count ) );
    }
    __forceinline static constexpr uint64_t rotrq( uint64_t value, int count )
    {
        if ( std::is_constant_evaluated() )
            count %= 64;
        return ( value >> count ) | ( value << ( 64 - count ) );
    }

    // Declare _?mul128
    //
    using int128_t =  __int128;
    using uint128_t = unsigned __int128;

    __forceinline static uint64_t _umul128( uint64_t _Multiplier, uint64_t _Multiplicand, uint64_t* _HighProduct )
    {
        uint128_t _Product = uint128_t( _Multiplicand ) * _Multiplier;
        *_HighProduct = uint64_t( _Product >> 64 );
        return uint64_t( _Product );
    }

    __forceinline static int64_t _mul128( int64_t _Multiplier, int64_t _Multiplicand, int64_t* _HighProduct )
    {
        int128_t _Product = int128_t( _Multiplier ) * _Multiplicand;
        *_HighProduct = int64_t( uint128_t( _Product ) >> 64 );
        return int64_t( _Product );
    }

    // Declare _?mulh
    //
    __forceinline static int64_t __mulh( int64_t _Multiplier, int64_t _Multiplicand )
    {
        int64_t HighProduct;
        _mul128( _Multiplier, _Multiplicand, &HighProduct );
        return HighProduct;
    }

    __forceinline static uint64_t __umulh( uint64_t _Multiplier, uint64_t _Multiplicand )
    {
        uint64_t HighProduct;
        _umul128( _Multiplier, _Multiplicand, &HighProduct );
        return HighProduct;
    }
#endif