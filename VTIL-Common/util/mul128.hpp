#pragma once
#include <stdint.h>

#ifndef _MSC_VER
static uint64_t _umul128( uint64_t _Multiplier, uint64_t _Multiplicand, uint64_t* _HighProduct )
{
    uint64_t LowProduct;
    uint64_t HighProduct;

    __asm__(
        "mulq  %[b]\n"
        :"=d"( HighProduct ), "=a"( LowProduct )
        : "1"( _Multiplier ), [ b ]"rm"( _Multiplicand ) );

    *_HighProduct = HighProduct;
    return LowProduct;
}

static int64_t _mul128( int64_t _Multiplier, int64_t _Multiplicand, int64_t* _HighProduct )
{
    int64_t LowProduct;
    int64_t HighProduct;

    __asm__(
        "imulq  %[b]\n"
        :"=d"( HighProduct ), "=a"( LowProduct )
        : "1"( _Multiplier ), [ b ]"rm"( _Multiplicand ) );

    *_HighProduct = HighProduct;
    return LowProduct;
}

static int64_t __mulh( int64_t _Multiplier, int64_t _Multiplicand )
{
    int64_t HighProduct;
    _mul128( _Multiplier, _Multiplicand, &HighProduct );
    return HighProduct;
}

static uint64_t __umulh( uint64_t _Multiplier, uint64_t _Multiplicand )
{
    uint64_t HighProduct;
    _umul128( _Multiplier, _Multiplicand, &HighProduct );
    return HighProduct;
}
#else
#include <intrin.h>
#endif