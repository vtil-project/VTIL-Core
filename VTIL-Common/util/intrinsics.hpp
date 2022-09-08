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
#include <cstdint>

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
#else
    #define unreachable() __builtin_unreachable()
    #define __forceinline __attribute__((always_inline))
    #define _AddressOfReturnAddress() ((void*)__builtin_frame_address(0))
    #define FUNCTION_NAME __PRETTY_FUNCTION__

#if defined(__x86_64__)
    #include <emmintrin.h>
    // Declare _?mul128
    //
    __forceinline static uint64_t _umul128( uint64_t _Multiplier, uint64_t _Multiplicand, uint64_t* _HighProduct )
    {
        uint64_t LowProduct;
        uint64_t HighProduct;

        __asm__( "mulq  %[b]"
                 :"=d"( HighProduct ), "=a"( LowProduct )
                 : "1"( _Multiplier ), [ b ]"rm"( _Multiplicand ) );

        *_HighProduct = HighProduct;
        return LowProduct;
    }

    __forceinline static int64_t _mul128( int64_t _Multiplier, int64_t _Multiplicand, int64_t* _HighProduct )
    {
        int64_t LowProduct;
        int64_t HighProduct;

        __asm__( "imulq  %[b]"
                 :"=d"( HighProduct ), "=a"( LowProduct )
                 : "1"( _Multiplier ), [ b ]"rm"( _Multiplicand ) );

        *_HighProduct = HighProduct;
        return LowProduct;
    }
#else

    #define _mm_pause() std::this_thread::yield()

    // Source: https://stackoverflow.com/a/31662911
    __forceinline static void _umul64wide( uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo )
    {
        uint64_t a_lo = (uint64_t)(uint32_t)a;
        uint64_t a_hi = a >> 32;
        uint64_t b_lo = (uint64_t)(uint32_t)b;
        uint64_t b_hi = b >> 32;

        uint64_t p0 = a_lo * b_lo;
        uint64_t p1 = a_lo * b_hi;
        uint64_t p2 = a_hi * b_lo;
        uint64_t p3 = a_hi * b_hi;

        uint32_t cy = (uint32_t)(((p0 >> 32) + (uint32_t)p1 + (uint32_t)p2) >> 32);

        *lo = p0 + (p1 << 32) + (p2 << 32);
        *hi = p3 + (p1 >> 32) + (p2 >> 32) + cy;
    }

    __forceinline static void _mul64wide( int64_t a, int64_t b, int64_t *hi, int64_t *lo )
    {
        _umul64wide ((uint64_t)a, (uint64_t)b, (uint64_t *)hi, (uint64_t *)lo);
        if (a < 0LL) *hi -= b;
        if (b < 0LL) *hi -= a;
    }

    __forceinline static uint64_t _umul128( uint64_t _Multiplier, uint64_t _Multiplicand, uint64_t* _HighProduct )
    {
        uint64_t LowProduct;
        uint64_t HighProduct;
        _umul64wide (_Multiplier, _Multiplicand, &HighProduct, &LowProduct);
        return LowProduct;
    }

    __forceinline static int64_t _mul128( int64_t _Multiplier, int64_t _Multiplicand, int64_t* _HighProduct )
    {
        int64_t LowProduct;
        int64_t HighProduct;
        _mul64wide (_Multiplier, _Multiplicand, &HighProduct, &LowProduct);
        return LowProduct;
    }

#endif

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