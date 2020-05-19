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
#include "operators.hpp"
#include "../util/mul128.hpp"

#pragma warning(push)
#pragma warning(disable: 4244)
namespace vtil::math
{
    // Calculates the size of the result after after the application of the operator [id] on the operands.
    //
    bitcnt_t result_size( operator_id id, bitcnt_t bcnt_lhs, bitcnt_t bcnt_rhs )
    {
        static_assert( round_bit_count( bit_index_size ) == bit_index_size, "Bit-index size must be rounded by default." );

        switch ( id )
        {
            // - Operators that work with bit-indices.
            //
            case operator_id::popcnt:         return bit_index_size;
            case operator_id::bit_count:      return bit_index_size;

            // - Unary and parameterized unary-like operators.
            //
            case operator_id::negate:
            case operator_id::bitwise_not:
            case operator_id::mask:
            case operator_id::value_if:       return round_bit_count( bcnt_rhs );
            case operator_id::shift_right:
            case operator_id::shift_left:
            case operator_id::rotate_right:
            case operator_id::rotate_left:    return round_bit_count( bcnt_lhs );

            // - Boolean operators.           
            //                                
            case operator_id::bit_test:
            case operator_id::greater:
            case operator_id::greater_eq:
            case operator_id::equal:
            case operator_id::not_equal:
            case operator_id::less_eq:
            case operator_id::less:
            case operator_id::ugreater:
            case operator_id::ugreater_eq:
            case operator_id::uless_eq:
            case operator_id::uless:          return 1;

            // - Resizing operators should not call into this helper.
            //
            case operator_id::cast:
            case operator_id::ucast:          unreachable();
        }

        // - Rest default to maximum operand size.
        //
        return round_bit_count( std::max( bcnt_lhs, bcnt_rhs ) );
    }

    // Applies the specified operator [id] on left hand side [lhs] and right hand side [rhs]
    // and returns the output as a masked unsigned 64-bit integer <0> and the final size <1>.
    //
    std::pair<uint64_t, bitcnt_t> evaluate( operator_id id, bitcnt_t bcnt_lhs, uint64_t lhs, bitcnt_t bcnt_rhs, uint64_t rhs )
    {
        // Normalize the input.
        //
        const operator_desc* desc = descriptor_of( id );
        if ( bcnt_lhs != 64 && desc->operand_count != 1 )  
            lhs = desc->is_signed ? sign_extend( lhs, bcnt_lhs ) : zero_extend( lhs, bcnt_lhs );
        if ( bcnt_rhs != 64 )  
            rhs = desc->is_signed ? sign_extend( rhs, bcnt_rhs ) : zero_extend( rhs, bcnt_rhs );

        // Create aliases for signed values to avoid ugly casts.
        //
        int64_t& ilhs = ( int64_t& ) lhs;
        int64_t& irhs = ( int64_t& ) rhs;

        // Calculate the result of the operation.
        //
        uint64_t result = 0;
        bitcnt_t bcnt_res = result_size( id, bcnt_lhs, bcnt_rhs );
        switch ( id )
        {
            // - Bitwise operators.
            //
            case operator_id::bitwise_not:      result = ~rhs;                                                      break;
            case operator_id::bitwise_and:      result = lhs & rhs;                                                 break;
            case operator_id::bitwise_or:       result = lhs | rhs;                                                 break;
            case operator_id::bitwise_xor:      result = lhs ^ rhs;                                                 break;
            case operator_id::shift_right:      result = rhs >= bcnt_lhs ? 0 : lhs >> rhs;                          break;
            case operator_id::shift_left:       result = rhs >= bcnt_lhs ? 0 : lhs << rhs;                          break;
            case operator_id::rotate_right:     result = ( lhs >> ( rhs % bcnt_lhs ) )
                                                       | ( lhs << ( bcnt_lhs - ( rhs % bcnt_lhs ) ) );              break;
            case operator_id::rotate_left:      result = ( lhs << ( rhs % bcnt_lhs ) )
                                                       | ( lhs >> ( bcnt_lhs - ( rhs % bcnt_lhs ) ) );              break;
            // - Arithmetic operators.                                                          
            //                                                                                  
            case operator_id::negate:           result = -irhs;                                                     break;
            case operator_id::add:              result = ilhs + irhs;                                               break;
            case operator_id::subtract:         result = ilhs - irhs;                                               break;
            case operator_id::multiply_high:    result = bcnt_res == 64
                                                        ? __mulh( ilhs, irhs )
                                                        : uint64_t( ilhs * irhs ) >> bcnt_res;                      break;
            case operator_id::umultiply_high:   result = bcnt_res == 64
                                                        ? __umulh( lhs, rhs )
                                                        : ( lhs * rhs ) >> bcnt_res;                                break;
            case operator_id::multiply:         result = ilhs * irhs;                                               break;
            case operator_id::umultiply:        result = lhs * rhs;                                                 break;
            case operator_id::divide:           result = ilhs / irhs;                                               break;
            case operator_id::udivide:          result = lhs / rhs;                                                 break;
            case operator_id::remainder:        result = ilhs % irhs;                                               break;
            case operator_id::uremainder:       result = lhs % rhs;                                                 break;

            // - Special operators.                                                          
            //                                                                                  
            case operator_id::cast:             result = ilhs, bcnt_res = rhs;                                      break;
            case operator_id::ucast:            result = lhs,  bcnt_res = rhs;                                      break;
            case operator_id::popcnt:           result = popcnt( rhs );                                             break;
            case operator_id::bit_test:         result = ( lhs >> rhs ) & 1;                                        break;
            case operator_id::mask:             result = fill( bcnt_rhs );                                          break;
            case operator_id::bit_count:        result = bcnt_rhs;                                                  break;
            case operator_id::value_if:         result = ( lhs & 1 ) ? rhs : 0;                                     break;

            // - MinMax operators
            //
            case operator_id::umin_value:       result = std::min( lhs, rhs );                                      break;
            case operator_id::umax_value:       result = std::max( lhs, rhs );                                      break;
            case operator_id::min_value:        result = std::min( ilhs, irhs );                                    break;
            case operator_id::max_value:        result = std::max( ilhs, irhs );                                    break;

            // - Comparison operators
            //
            case operator_id::greater:          result = ilhs > irhs;                                               break;
            case operator_id::greater_eq:       result = ilhs >= irhs;                                              break;
            case operator_id::equal:            result = ilhs == irhs;                                              break;
            case operator_id::not_equal:        result = ilhs != irhs;                                              break;
            case operator_id::uequal:           result = lhs == rhs;                                                break;
            case operator_id::unot_equal:       result = lhs != rhs;                                                break;
            case operator_id::less_eq:          result = ilhs <= irhs;                                              break;
            case operator_id::less:             result = ilhs < irhs;                                               break;
            case operator_id::ugreater:         result = lhs > rhs;                                                 break;
            case operator_id::ugreater_eq:      result = lhs >= rhs;                                                break;
            case operator_id::uless_eq:         result = lhs <= rhs;                                                break;
            case operator_id::uless:            result = lhs < rhs;                                                 break;
            default:                            unreachable();
        }

        // Mask and return.
        //
        return { result & fill( bcnt_res ), bcnt_res };
    }

    // Applies the specified operator [op] on left hand side [lhs] and right hand side [rhs] where
    // input and output values are expressed in the format of bit-vectors with optional unknowns,
    // and no size constraints.
    //
    bit_vector evaluate_partial( operator_id op, const bit_vector& lhs, const bit_vector& rhs )
    {
        // If no unknown bits, redirect to more efficient math::evaluate()
        //
        if ( !lhs.unknown_mask() && !rhs.unknown_mask() )
        {
            auto [val, size] = evaluate( op, lhs.size(), lhs.known_one(), rhs.size(), rhs.known_one() );
            return { val, size };
        }

        switch ( op )
        {
            //
            // Basic bitwise operators.
            //
            // ####################################################################################################################################
            case operator_id::bitwise_not:
                // Unknown mask does not change, known bits are flipped.
                //
                return bit_vector{ ~rhs.known_one(), rhs.unknown_mask(), rhs.size() };

            case operator_id::bitwise_and:
                // Bitwise AND known bits, unknown mask is unset if one side had a known zero.
                //
                return bit_vector
                { 
                    lhs.known_one() & rhs.known_one(), 
                    ( lhs.unknown_mask() | rhs.unknown_mask() ) & ~( lhs.known_zero() | rhs.known_zero() ), 
                    std::min( lhs.size(), rhs.size() ) 
                }.resize( std::max( lhs.size(), rhs.size() ) );

            case operator_id::bitwise_or:
                // Bitwise OR known bits, unknown mask is unset if one side had a known one.
                //
                return bit_vector
                { 
                    lhs.known_one() | rhs.known_one(), 
                    ( lhs.unknown_mask() | rhs.unknown_mask() ) & ~( lhs.known_one() | rhs.known_one() ), 
                    std::max( lhs.size(), rhs.size() ) 
                };

            case operator_id::bitwise_xor:
                // Bitwise XOR known bits, unknown mask is merged.
                //
                return bit_vector
                { 
                    lhs.known_one() ^ rhs.known_one(), 
                    lhs.unknown_mask() | rhs.unknown_mask(), 
                    std::max( lhs.size(), rhs.size() ) 
                };
                
            //
            // Rotations and shifts.
            //
            // ####################################################################################################################################
            case operator_id::shift_right:
                // If shift count is known:
                //
                if ( auto n = rhs.get() )
                {
                    // If shifting more bits than we have, return 0.
                    //
                    uint64_t shr_count = n.value();
                    if ( shr_count >= lhs.size() )      return bit_vector( 0, lhs.size() );

                    // Return shifted masks, vector will normalize rest.
                    //
                    return { lhs.known_one() >> shr_count, lhs.unknown_mask() >> shr_count, lhs.size() };
                }
                // If shift count is unknown, return unknown bit-vector or 0 if input was only consisting of zeros.
                //
                return lhs.all_zero() ? lhs : bit_vector( lhs.size() );

            case operator_id::shift_left:
                // If shift count is known:
                //
                if ( auto n = rhs.get() )
                {
                    // If shifting more bits than we have, return 0.
                    //
                    uint64_t shl_count = n.value();
                    if ( shl_count >= lhs.size() )      return bit_vector( 0, lhs.size() );

                    // Return shifted masks, vector will normalize rest.
                    //
                    return { lhs.known_one() << shl_count, lhs.unknown_mask() << shl_count, lhs.size() };
                }
                // If shift count is unknown, return unknown bit-vector or 0 if input was only consisting of zeros.
                //
                return lhs.all_zero() ? lhs : bit_vector( lhs.size() );

            case operator_id::rotate_right:
                // If rotation count is known, return rotated masks, vector will normalize rest.
                //
                if ( auto n = rhs.get() )
                {
                    uint64_t shr_count = n.value() % lhs.size();
                    uint64_t shl_count = lhs.size() - shr_count;
                    return
                    {
                        (    lhs.known_one() >> shr_count ) | (    lhs.known_one() << shl_count ),
                        ( lhs.unknown_mask() >> shr_count ) | ( lhs.unknown_mask() << shl_count ),
                        lhs.size()
                    };
                }
                // If rotation count is unknown, return unknown bit-vector or 0/1 if input was only consisting of the same bit state.
                //
                return ( lhs.all_one() || lhs.all_zero() ) ? lhs : bit_vector( lhs.size() );

            case operator_id::rotate_left:
                // If rotation count is known, return rotated masks, vector will normalize rest.
                //
                if ( auto n = rhs.get() )
                {
                    uint64_t shl_count = n.value() % lhs.size();
                    uint64_t shr_count = lhs.size() - shl_count;
                    return
                    {
                        (    lhs.known_one() >> shr_count ) | (    lhs.known_one() << shl_count ),
                        ( lhs.unknown_mask() >> shr_count ) | ( lhs.unknown_mask() << shl_count ),
                        lhs.size()
                    };
                }
                // If rotation count is unknown, return unknown bit-vector or 0/1 if input was only consisting of the same bit state.
                //
                return ( lhs.all_one() || lhs.all_zero() ) ? lhs : bit_vector( lhs.size() );
                
            //
            // Arithmetic operators:
            // - TODO: Re-implement *fixed* O(1) solution for ADD SUB and NEG.
            //
            // ####################################################################################################################################
            case operator_id::add:
            {
                    // Create the temp holding the new bit vector.
                    //
                    uint64_t known_mask = 0;
                    uint64_t unknown_mask = 0;
                    bitcnt_t out_size = std::max( lhs.size(), rhs.size() );

                    // For each bit in the output size:
                    //
                    bit_vector lhs_sx = bit_vector{ lhs }.resize( out_size, true );
                    bit_vector rhs_sx = bit_vector{ rhs }.resize( out_size, true );
                    bit_state carry = bit_state::zero;
                    for ( int i = 0; i < out_size; i++ )
                    {
                        // Get current bits and choose the branch depending on the type:
                        //
                        bit_state a = lhs_sx[ i ];
                        bit_state b = rhs_sx[ i ];
                        if ( const int unk_count = ( a == bit_state::unknown ) + ( b == bit_state::unknown ) + ( carry == bit_state::unknown ) )
                        {
                            const int one_count = ( a == bit_state::one ) + ( b == bit_state::one ) + ( carry == bit_state::one );
                            const int zero_count = 3 - one_count - unk_count;
                        
                            // Carry is one if 2 elements are 1, zero if 2 elements are zero
                            // and unknown otherise.
                            //
                            if ( one_count == 2 )       carry = bit_state::one;
                            else if ( zero_count == 2 ) carry = bit_state::zero;
                            else                        carry = bit_state::unknown;

                            // Output is always unknown.
                            //
                            unknown_mask |= 1ull << i;
                        }
                        else if ( a == b )
                        {
                            // Duplicated element propagates as carry, output is current carry.
                            //
                            known_mask |= uint64_t( carry == bit_state::one ) << i;
                            carry = a;
                        }
                        else if ( a != b )
                        {
                            // Carry propagates as is, output is inverse of current carry.
                            //
                            known_mask |= uint64_t( carry == bit_state::zero ) << i;
                        }
                    }
                    return bit_vector( known_mask, unknown_mask, out_size );

                    /*a = ( lhs.unknown_mask() | lhs.known_one() ) + ( rhs.unknown_mask() | rhs.known_one() );
                    b = ( lhs.known_one()                      ) + ( rhs.known_one()                      );

                    return
                    {
                        a & b,
                        ~( a & b ) & ~( ~a & ~b ),
                        std::max( lhs.size(), rhs.size() )
                    };
                    break;*/
            }

            case operator_id::negate:
                // -A = 0-A
                //
                return evaluate_partial( operator_id::subtract, { 0, rhs.size() }, rhs );
                
                /*a = mask( rhs.size() ) & -__sx64( ( rhs.unknown_mask() | rhs.known_one() ), rhs.size() );
                b = mask( rhs.size() ) & -__sx64( ( rhs.known_one() ),                      rhs.size() );

                return 
                {
                    a & b,
                    ~( a & b ) & ~( ~a & ~b ),
                    rhs.size()
                };
                break;*/
            case operator_id::subtract:
                // A-B = ~(~A+B)
                //
                return  evaluate_partial( operator_id::bitwise_not, {},
                                          evaluate_partial( operator_id::add,
                                            evaluate_partial( operator_id::bitwise_not, {}, lhs ),
                                            rhs ) );
                
                /*a = ( lhs.unknown_mask() | lhs.known_one() ) - ( rhs.known_one()                      );
                b = ( lhs.known_one()                      ) - ( rhs.unknown_mask() | rhs.known_one() );

                return
                {
                    a & b,
                    ~( a & b ) & ~( ~a & ~b ),
                    std::max( lhs.size(), rhs.size() )
                };
                break;*/
            
            //
            // Bitwise specials.
            //
            // ####################################################################################################################################
            case operator_id::ucast:
                // Get new size from RHS as constant, and resize LHS to be of size [RHS] with zero extension if relevant.
                //
                if ( auto new_size = rhs.get() )  return bit_vector( lhs ).resize( *new_size, false );
                else                              unreachable();

            case operator_id::cast:
                // Get new size from RHS as constant, and resize LHS to be of size [RHS] with sign extension if relevant.
                //
                if ( auto new_size = rhs.get() )  return bit_vector( lhs ).resize( *new_size, true );
                else                              unreachable();

            case operator_id::popcnt:
                // Cannot be calculated with unknown values, return unknown of expected size.
                //
                return bit_vector( popcnt( lhs.known_one() | lhs.unknown_mask() ) ).resize( bit_index_size );

            case operator_id::bit_test:
                // If we can get the index being tested as constant, try to evaluate. 
                //
                if ( auto index = rhs.get() )
                {
                    return 
                    { 
                        ( lhs.known_one() >> rhs.known_one() ) & 1, 
                        ( lhs.unknown_mask() >> rhs.known_one() ) & 1, 
                        1 
                    };
                }
                // Otherwise, return unknown of one bit.
                //
                return bit_vector( 1 );

            case operator_id::mask:
                // Return the mask of the vector as is.
                //
                return bit_vector( rhs.value_mask(), rhs.size() );

            case operator_id::bit_count:
                // Return the number of bits in the vector as is.
                //
                return bit_vector( rhs.size(), bit_index_size );

            case operator_id::value_if:
                // Try to evaluate the (x&1)?y:0 statement.
                //
                if ( lhs.known_one() & 1 )         return rhs;
                else if ( lhs.unknown_mask() & 1 ) return bit_vector{ rhs.size() };
                else                               return bit_vector{ 0, rhs.size() };

            
            //
            // Complex arithmetic operators.
            // - TODO: Whole thing :)
            //
            // ####################################################################################################################################
            case operator_id::multiply_high:
            case operator_id::multiply:
            case operator_id::divide:
            case operator_id::remainder:
            case operator_id::umultiply_high:
            case operator_id::umultiply:
            case operator_id::udivide:
            case operator_id::uremainder:
                return bit_vector( std::max( rhs.size(), lhs.size() ) );

                
            //
            // MinMax operators:
            //
            // ####################################################################################################################################
            case operator_id::min_value:
            case operator_id::max_value:
            case operator_id::umin_value:
            case operator_id::umax_value:
            {
                // Map each min-max to a comperator.
                //
                operator_id cmp_id;
                switch ( op )
                {
                    case operator_id::umin_value:   cmp_id = operator_id::uless;        break;
                    case operator_id::umax_value:   cmp_id = operator_id::ugreater_eq;  break;
                    case operator_id::min_value:    cmp_id = operator_id::less;         break;
                    case operator_id::max_value:    cmp_id = operator_id::greater_eq;   break;
                    default: unreachable();
                }

                // cmp<>(A,B) ? A : B
                bit_state cmp_res = evaluate_partial( cmp_id, lhs, rhs )[ 0 ];
                bitcnt_t cmp_out_size = std::max( lhs.size(), rhs.size() );
                switch ( cmp_res )
                {
                    case bit_state::one:      return bit_vector{ lhs }.resize( cmp_out_size );
                    case bit_state::zero:      return bit_vector{ rhs }.resize( cmp_out_size );
                    case bit_state::unknown:  return bit_vector{ cmp_out_size };
                    default: unreachable();
                }
            }
            
            //
            // Signed comparisons:
            //
            // ####################################################################################################################################
            case operator_id::greater:
            case operator_id::greater_eq:
            case operator_id::less_eq:
            case operator_id::less:
            {
                // Fail if sign bits are not known
                //
                bit_state rhs_sign = rhs[ rhs.size() - 1 ];
                if ( rhs_sign == bit_state::unknown )  return bit_vector( 1 );
                bit_state lhs_sign = lhs[ lhs.size() - 1 ];
                if ( lhs_sign == bit_state::unknown )  return bit_vector( 1 );

                // If LHS is negative and RHS is positive, <, <= wins.
                //
                if ( lhs_sign == bit_state::one && rhs_sign == bit_state::zero )
                    return bit_vector( op == operator_id::less || op == operator_id::less_eq, 1 );

                // If RHS is negative and LHS is positive, >, >= wins.
                //
                if ( rhs_sign == bit_state::one && lhs_sign == bit_state::zero )
                    return bit_vector( op == operator_id::greater || op == operator_id::greater_eq, 1 );

                // For each bit index we should compare:
                //
                bitcnt_t cmp_size = std::max( lhs.size(), rhs.size() );
                bit_vector lhs_sx = bit_vector{ lhs }.resize( cmp_size, true );
                bit_vector rhs_sx = bit_vector{ rhs }.resize( cmp_size, true );
                for ( int i = cmp_size - 1; i >= 0; i-- )
                {
                    // If any of the bits are unknown, result is unknown.
                    //
                    if ( lhs_sx[ i ] == bit_state::unknown || rhs_sx[ i ] == bit_state::unknown )
                        return bit_vector( 1 );

                    // If LHS is one and RHS is zero, >, >= and != wins.
                    //
                    if ( lhs_sx[ i ] == bit_state::one && rhs_sx[ i ] == bit_state::zero )
                        return bit_vector( op == operator_id::greater || op == operator_id::greater_eq, 1 );

                    // If RHS is one and LHS is zero, <, <= and != wins.
                    //
                    if ( rhs_sx[ i ] == bit_state::one && lhs_sx[ i ] == bit_state::zero )
                        return bit_vector( op == operator_id::less || op == operator_id::less_eq, 1 );
                }

                // If completely equivalent (when sign extended), <=, >= wins.
                //
                return bit_vector( op == operator_id::less_eq || op == operator_id::greater_eq, 1 );
            }
            
            //
            // Equality checks:
            //
            // ####################################################################################################################################
            case operator_id::equal:
            case operator_id::not_equal:
            {
                // Fail if sign bits are not known
                //
                bit_state rhs_sign = rhs[ rhs.size() - 1 ];
                if ( rhs_sign == bit_state::unknown )  return bit_vector( 1 );
                bit_state lhs_sign = lhs[ lhs.size() - 1 ];
                if ( lhs_sign == bit_state::unknown )  return bit_vector( 1 );

                // If signs do not match, != wins.
                //
                if ( lhs_sign != rhs_sign )
                    return bit_vector( op == operator_id::not_equal, 1 );

                // Sign extend both.
                //
                bitcnt_t cmp_size = std::max( lhs.size(), rhs.size() );
                bit_vector lhs_sx = bit_vector{ lhs }.resize( cmp_size, true );
                bit_vector rhs_sx = bit_vector{ rhs }.resize( cmp_size, true );

                // If known zero of one side maps to known one of other and vice versa, != wins.
                //
                if ( ( lhs_sx.known_zero() & rhs_sx.known_one() ) || ( lhs_sx.known_one() & rhs_sx.known_zero() ) )
                    return bit_vector( op == operator_id::not_equal, 1 );

                // If any of the bits are unknown, result is unknown.
                //
                if ( lhs_sx.unknown_mask() | rhs_sx.unknown_mask() )
                    return bit_vector( 1 );

                // Simply compare all bits and adjust to the operator result.
                //
                return bit_vector( ( op == operator_id::not_equal ) ^ ( lhs_sx.known_one() == rhs_sx.known_one() ), 1 );
            }
                
            //
            // Unsigned comparisons:
            //
            // ####################################################################################################################################
            case operator_id::ugreater:
            case operator_id::ugreater_eq:
            case operator_id::uless_eq:
            case operator_id::uless:
                // For each bit index we should compare:
                //
                for ( int i = std::max( lhs.size(), rhs.size() ) - 1; i >= 0; i-- )
                {
                    // If any of the bits are unknown, result is unknown.
                    //
                    if ( lhs[ i ] == bit_state::unknown || rhs[ i ] == bit_state::unknown ) 
                        return bit_vector( 1 );

                    // If LHS is one and RHS is zero, >, >= wins.
                    //
                    if ( lhs[ i ] == bit_state::one && rhs[ i ] == bit_state::zero ) 
                        return bit_vector( op == operator_id::ugreater || op == operator_id::ugreater_eq, 1 );

                    // If RHS is one and LHS is zero, <, <= wins.
                    //
                    if ( rhs[ i ] == bit_state::one && lhs[ i ] == bit_state::zero ) 
                        return bit_vector( op == operator_id::uless || op == operator_id::uless_eq, 1 );
                }

                // If completely equivalent (when zero extended), <=, >= wins.
                //
                return bit_vector( op == operator_id::uless_eq || op == operator_id::ugreater_eq, 1 );
            
            //
            // Unsigned equality checks:
            //
            // ####################################################################################################################################
            case operator_id::uequal:
            case operator_id::unot_equal:
                // If known zero of one side maps to known one of other and vice versa, != wins.
                //
                if ( ( lhs.known_zero() & rhs.known_one() ) || ( lhs.known_one() & rhs.known_zero() ) )
                    return bit_vector( op == operator_id::unot_equal, 1 );

                // If any of the bits are unknown, result is unknown.
                //
                if ( lhs.unknown_mask() | rhs.unknown_mask() )
                    return bit_vector( 1 );

                // Simply compare all bits and adjust to the operator result.
                //
                return bit_vector( ( op == operator_id::unot_equal ) ^ ( lhs.known_one() == rhs.known_one() ), 1 );
        }
        unreachable();
    }
};
#pragma warning(pop)