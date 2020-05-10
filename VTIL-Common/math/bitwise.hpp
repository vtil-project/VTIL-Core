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
#include <stdint.h>
#include <math.h>
#include <optional>
#include <type_traits>
#include "../util/reducable.hpp"
#include "../io/asserts.hpp"

// Declare the type we will used for bit lenghts of data.
// - We are using int instead of char since most operations will end up casting
//   this value to an integer anyway and since char does not provide us any intrinsic
//   safety either this only hurts us in terms of performance.
//
using bitcnt_t = int;

namespace vtil::math
{
    // Sizeof equivalent in bits.
    //
    template<typename T>
    static constexpr bitcnt_t bitcnt = sizeof( T ) * 8;

    // Extracts the sign bit from the given value.
    //
    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    static constexpr bool sgn( T type ) { return bool( type >> ( bitcnt<T> - 1 ) ); }

    // Implement platform-indepdenent popcnt.
    //
    static constexpr bitcnt_t popcnt( uint64_t x )
    {
        // https://www.chessprogramming.org/Population_Count#The_PopCount_routine
        //
        x = x - ( x >> 1 ) & 0x5555555555555555;
        x = ( x & 0x3333333333333333 ) + ( ( x >> 2 ) & 0x3333333333333333 );
        x = ( x + ( x >> 4 ) ) & 0x0f0f0f0f0f0f0f0f;
        x = ( x * 0x0101010101010101 ) >> 56;
        return bitcnt_t( x );
    }

    // Generate a mask for the given variable size and offset.
    //
    static constexpr uint64_t fill( bitcnt_t bit_count, bitcnt_t bit_offset = 0 )
    {
        if ( bit_offset >= 64 ) return 0;
        return ( ( ~0ull ) >> ( 64 - bit_count ) ) << bit_offset;
    }

    // Fills the bits of the uint64_t type after the given offset with the sign bit.
    // - We accept an [uint64_t] as the sign "bit" instead of a for 
    //   the sake of a further trick we use to avoid branches.
    //
    static constexpr uint64_t fill_sign( uint64_t sign, bitcnt_t bit_offset = 0 )
    {
        // The XOR operation with 0b1 flips the sign bit, after which when we subtract
        // one to create 0xFF... for (1) and 0x00... for (0).
        // - We could have also done [s *= ~0ull], but it's slower since:
        //    1) XOR ~= [#μop: 1, latency: 1]
        //    2) SUB ~= [#μop: 1, latency: 1]
        //    vs
        //    1) MUL ~= [#μop: 3, latency: 3]
        //
        return ( ( sign ^ 1 ) - 1 ) << bit_offset;
    }

    // Extends the given integral type into uint64_t or int64_t.
    //
    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    static auto imm_extend( T imm )
    {
        if constexpr ( std::is_signed_v<T> )
            return ( int64_t ) imm;
        else
            return ( uint64_t ) imm;
    }

    // Zero extends the given integer.
    //
    static uint64_t zero_extend( uint64_t value, bitcnt_t bcnt_src )
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
        value &= fill( bcnt_src );
        return value;
    }

    // Sign extends the given integer.
    //
    static int64_t sign_extend( uint64_t value, bitcnt_t bcnt_src )
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
        value &= fill( bcnt_src );

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
    class bit_vector : public reducable<bit_vector>
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
        bitcnt_t bit_count = 0;

    public:
        // Default constructor, will result in invalid bit-vector.
        //
        bit_vector() = default;

        // Constructs a bit-vector where all bits are set according to the state.
        // - Declared explicit to avoid construction from integers.
        //
        explicit bit_vector( bitcnt_t bit_count ) :                                      
            bit_count( bit_count ),     unknown_bits( fill( bit_count ) ),                  known_bits( 0 ) {}
                                                                                                                                          
        // Constructs a bit-vector where all bits are known.												                              
        //																									                              
        bit_vector( uint64_t value, bitcnt_t bit_count ) :                               
            bit_count( bit_count ),     unknown_bits( 0 ),                                  known_bits( value & fill( bit_count ) ) {}
                                                                                                                                            
        // Constructs a bit-vector where bits are partially known.											                                
        //																									                                
        bit_vector( uint64_t known_bits, uint64_t unknown_bits, bitcnt_t bit_count ) :   
            bit_count( bit_count ),     unknown_bits( unknown_bits & fill( bit_count ) ),   known_bits( known_bits & ~( unknown_bits & fill( bit_count ) ) ) {}

        // Some helpers to access the internal state.
        //
        uint64_t value_mask() const { return fill( bit_count ); }
        uint64_t unknown_mask() const { return unknown_bits; }
        uint64_t known_mask() const { return fill( bit_count ) & ~unknown_bits; }
        uint64_t known_one() const { return known_bits; }
        uint64_t known_zero() const { return ~( unknown_bits | known_bits ); }
        bool all_zero() const { return unknown_bits == 0 && !known_bits; }
        bool all_one() const { return unknown_bits == 0 && ( known_bits == fill( bit_count ) ); }
        bool is_valid() const { return bit_count != 0; }
        bool is_known() const { return bit_count && unknown_bits == 0; }
        bool is_unknown() const { return !bit_count || unknown_bits != 0; }
        bitcnt_t size() const { return bit_count; }

        // Gets the value represented, and nullopt if vector has unknown bits.
        //
        template<typename type>
        std::optional<type> get() const
        {
            if ( is_known() )
            {
                if constexpr ( std::is_signed_v<type> )
                    return ( type ) sign_extend( known_bits, bit_count );
                else
                    return ( type ) zero_extend( known_bits, bit_count );
            }
            return std::nullopt;
        }
        template<bool as_signed = false, typename type = std::conditional_t<as_signed, int64_t, uint64_t>>
        std::optional<type> get() const { return get<type>(); }

        // Extends or shrinks the the vector.
        //
        bit_vector& resize( bitcnt_t new_size, bool signed_cast = false )
        {
            fassert( 0 < new_size && new_size <= 64 );

            if( signed_cast && new_size > bit_count )
            {
                bit_state sign_bit = at( bit_count - 1 );
                bool sign_bit_unk = at( bit_count - 1 ) == bit_state::unknown;
                
                if ( sign_bit == bit_state::unknown )
                    unknown_bits |= fill( 64, bit_count );
                else if ( sign_bit == bit_state::one )
                    known_bits |= fill( 64, bit_count );
            }

            bit_count = new_size;
            known_bits &= fill( new_size );
            unknown_bits &= fill( new_size );
            return *this;
        }

        // Gets the state of the bit at the index given.
        //
        bit_state at( bitcnt_t n ) const
        {
            if ( unknown_bits & ( 1ull << n ) ) return bit_state::unknown;
            return bit_state( ( ( ( known_bits >> n ) & 1 ) << 1 ) - 1 );
        }
        bit_state operator[]( bitcnt_t n ) const { return at( n ); }

        // Conversion to human-readable format.
        //
        std::string to_string() const
        {
            std::string out;
            for ( int n = bit_count - 1; n >= 0; n-- )
            {
                uint64_t mask = 1ull << n;
                out += ( unknown_bits & mask ) ? '?' : ( known_bits & mask ) ? '1' : '0';
            }
            return out;
        }

        // Declare reduction.
        // - Note: Relative comparison operators should not be used for actual comparison 
        //         but are there for the use of sorted containers.
        //
        auto reduce() { return reference_as_tuple( unknown_bits, known_bits, bit_count ); }
    };
};