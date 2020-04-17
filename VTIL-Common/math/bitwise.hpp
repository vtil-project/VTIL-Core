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
// Furthermore, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information                   |
// |-------------------------|------------------------------------------------|
// | amd64/*                 | https://github.com/aquynh/capstone/            |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#pragma once
#include <stdint.h>
#include <math.h>
#include <optional>
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
    static uint64_t __zx64( uint64_t value, uint8_t bcnt_src )
    {
        // Use simple casts where possible.
        //
        switch ( bcnt_src )
        {
            case 1: return value & 1;
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
    static int64_t __sx64( uint64_t value, uint8_t bcnt_src )
    {
        // Use simple casts where possible.
        //
        switch ( bcnt_src )
        {
            case 1: return value & 1;             // Booleans cannot have sign bits by definition.
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

    // Return value from bit-vector lookup where the result can be either unknown or constant 0/1.
    //
    enum class bit_state : int8_t
    {
        zero = -1,
        unknown = 0,
        one = +1,
    };

    // Bit-vector holding 0 to 64 bits of value with optional unknowns.
    //
    class bit_vector
    {
        // Value of the known bits, mask of it can be found by [::known_mask()]
        // - Guaranteed to hold 0 for unknown bits.
        //
        uint64_t known_bits = 0;

        // Mask for the bit that we do not know.
        // - Guaranteed to hold 0 for known bits and for all bits above bit_count.
        //
        uint64_t unknown_bits = 0;

        // Number of bits this vector contains.
        //
        uint8_t bit_count = 0;

    public:
        // Default constructor, will result in invalid bit-vector.
        //
        bit_vector() = default;

        // Constructs a bit-vector where all bits are set according to the state.
        // - Declared explicit to avoid construction from integers.
        //
        explicit bit_vector( uint8_t bit_count ) :                                      bit_count( bit_count ),     unknown_bits( mask( bit_count ) ),                  known_bits( 0 ) {}
                                                                                                                                          
        // Constructs a bit-vector where all bits are known.												                              
        //																									                              
        bit_vector( uint64_t value, uint8_t bit_count ) :                               bit_count( bit_count ),     unknown_bits( 0 ),                                  known_bits( value & mask( bit_count ) ) {}
                                                                                                                                            
        // Constructs a bit-vector where bits are partially known.											                                
        //																									                                
        bit_vector( uint64_t known_bits, uint64_t unknown_bits, uint8_t bit_count ) :   bit_count( bit_count ),     unknown_bits( unknown_bits & mask( bit_count ) ),   known_bits( known_bits & ~( unknown_bits & mask( bit_count ) ) ) {}

        // Gets the mask of the whole vector.
        //
        inline uint64_t value_mask() const { return mask( bit_count ); }

        // Gets the mask for unknown bits.
        //
        inline uint64_t unknown_mask() const { return unknown_bits; }
        
        // Gets the mask for known bits.
        //
        inline uint64_t known_mask() const { return mask( bit_count ) & ~unknown_bits; }

        // Gets the mask of every known one.
        //
        inline uint64_t known_one() const { return known_bits; }
        
        // Gets the mask of every known zero.
        //
        inline uint64_t known_zero() const { return ~( unknown_bits | known_bits ); }

        // Checks if the vector consists of only zeros.
        //
        inline bool all_zero() const { return unknown_bits == 0 && !known_bits; }
        
        // Checks if the vector consists of only ones.
        //
        inline bool all_one() const { return unknown_bits == 0 && ( known_bits == mask( bit_count ) ); }

        // Checks if the vector is valid.
        //
        inline bool is_valid() const { return bit_count != 0; }

        // Checks if the vector value can be resolved.
        //
        inline bool is_known() const { return unknown_bits == 0; }
        inline bool is_unknown() const { return unknown_bits != 0; }
        
        // Gets the number of bits in the vector.
        //
        inline uint8_t size() const { return bit_count; }

        // Gets the value represented, and nullopt if vector has unknown bits.
        //
        template<bool sgn = false>
        inline std::optional<uint64_t> get() const { return is_known() ? std::optional{ sgn ? __sx64( known_bits, bit_count ) : __zx64( known_bits, bit_count ) } : std::nullopt; }

        // Extends or shrinks the the vector.
        //
        bit_vector& resize( uint8_t new_size, bool sign_extend = false )
        {
            fassert( 0 < new_size && new_size <= 64 );

            if( sign_extend && new_size > bit_count )
            {
                bit_state sign_bit = at( bit_count - 1 );
                bool sign_bit_unk = at( bit_count - 1 ) == bit_state::unknown;
                
                if ( sign_bit == bit_state::unknown )
                    unknown_bits |= mask( 64, bit_count );
                else if ( sign_bit == bit_state::one )
                    known_bits |= mask( 64, bit_count );
            }

            bit_count = new_size;
            known_bits &= mask( new_size );
            unknown_bits &= mask( new_size );
            return *this;
        }

        // Gets the state of the bit at the index given.
        //
        bit_state at( uint8_t n ) const
        {
            if ( unknown_bits & ( 1ull << n ) ) return bit_state::unknown;
            return bit_state( ( ( ( known_bits >> n ) & 1 ) << 1 ) - 1 );
        }
        inline bit_state operator[]( uint8_t n ) const { return at( n ); }

        // Conversion to human-readable format.
        //
        std::string to_string() const
        {
            std::string o;
            for ( int off = bit_count - 1; off >= 0; off-- )
            {
                uint64_t mask = 1ull << off;
                o += unknown_bits & mask ? '?' : known_bits & mask ? '1' : '0';
            }
            return o;
        }
    };
};