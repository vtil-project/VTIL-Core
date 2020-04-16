#pragma once
#include <stdint.h>
#include <math.h>
#include "..\io\asserts.hpp"

namespace vtil::math
{
    // Generate a mask for the given variable size and offset.
    //
    static constexpr uint64_t mask( uint8_t bit_count = 64, uint8_t bit_offset = 0 )
    {
        if ( bit_offset >= 64 ) return 0;
        return ( ( ~0ull ) >> ( 64 - bit_count ) ) << bit_offset;
    }

    // Zero extends the given integer.
    //
    static uint64_t zero_extend( uint64_t value, uint8_t bcnt_src )
    {
        // Use simple casts where possible.
        //
        switch ( bcnt_src )
        {
            case 8: return  *( uint8_t* ) &value;
            case 16: return *( uint16_t* ) &value;
            case 32: return *( uint32_t* ) &value;
            case 64: return *( uint64_t* ) &value;
        }

        // Make sure source size is non-zero.
        //
        fassert( bcnt_src != 0 );

        // Mask the value.
        //
        value &= mask( bcnt_src );
        return value;
    }

    // Sign extends the given integer.
    //
    static int64_t sign_extend( uint64_t value, uint8_t bcnt_src )
    {
        // Use simple casts where possible.
        //
        switch ( bcnt_src )
        {
            case 8: return  *( int8_t* ) &value;
            case 16: return *( int16_t* ) &value;
            case 32: return *( int32_t* ) &value;
            case 64: return *( int64_t* ) &value;
        }

        // Make sure source size is non-zero.
        //
        fassert( bcnt_src != 0 );

        // Extract sign bit.
        //
        uint64_t sign = ( value >> ( bcnt_src - 1 ) ) & 1;

        // Mask the value.
        //
        value &= mask( bcnt_src );

        // Extend the sign bit.
        // - Small trick is used here to avoid branches.
        //
        sign = ( ( sign ^ 1 ) - 1 ) << bcnt_src;
        return value | sign;
    }
};