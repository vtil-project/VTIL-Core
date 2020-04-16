// Copyright (c) 2020 Can Bölük and contributors of the VTIL Project		   
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
// Furthermode, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information				      |
// |-------------------------|------------------------------------------------|
// | amd64/*                 | https://github.com/aquynh/capstone/		      |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
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