// Copyright (c) 2020 Can B�l�k and contributors of the VTIL Project		   
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
#include <string>
#include <intrin.h>
#include <functional>
#include <algorithm>
#include "bitwise.hpp"

namespace vtil::math
{
    enum class operator_id
    {
        invalid,        // = <Invalid>

        // ------------------ Bitwise Operators ------------------ //

        // Bitwise modifiers:
        //
        bitwise_not,	// ~RHS

        // Basic bitwise operations:
        //
        bitwise_and,	// LHS&(RHS&...)
        bitwise_or,	    // LHS|(RHS|...)
        bitwise_xor,	// LHS^(RHS^...)

        // Distributing bitwise operations:
        //
        shift_right,	// LHS>>(RHS+...)
        shift_left,	    // LHS<<(RHS+...)
        rotate_right,   // LHS>](RHS+...)
        rotate_left,    // LHS[<(RHS+...)

        // ---------------- Arithmetic Operators ----------------- //

        // Arithmetic modifiers:
        //
        negate,	        // -RHS

        // Basic arithmetic operations:
        //
        add,	        // LHS+(RHS+...)
        substract,	    // LHS-(RHS+...)

        // Distributing arithmetic operations:
        //
        multiply_high,  // HI(LHS*RHS)
        multiply,       // LHS*(RHS*...)
        divide,         // LHS/(RHS*...)
        remainder,      // LHS%RHS

        umultiply_high, // < Unsigned variants of above >
        umultiply,      // 
        udivide,        // 
        uremainder,     // 

        // ----------------- Special Operators ----------------- //
        zero_extend,    // ZX(LHS, RHS)
        sign_extend,	// SX(LHS, RHS)
        popcnt,         // POPCNT(RHS)
        most_sig_bit,   // MSB(LHS) or RHS if none
        least_sig_bit,  // LSB(LHS) or RHS if none
        bit_test,	    // [LHS>>RHS]&1
        mask,	        // RHS.mask()
        bitcnt,	        // RHS.bitcount()
        value_if,	    // LHS&1 ? RHS : 0

        max_value,	    // LHS>=RHS ? LHS : RHS
        min_value,	    // LHS<=RHS ? LHS : RHS

        smax_value,	    // < Signed(!) variants of above >
        smin_value,	    //

        greater,	    // LHS > RHS
        greater_eq,	    // LHS >= RHS
        equal,	        // LHS == RHS
        not_equal,	    // LHS != RHS
        less_eq,	    // LHS <= RHS
        less,		    // LHS < RHS

        ugreater,	    // < Unsigned variants of above >
        ugreater_eq,	//
        uless_eq,	    //
        uless,		    //
    max,
    };

    // Basic properties of each operator.
    //
    struct operator_desc
    {
        // >0 if bitwise operations are preferred as operands, <0 if arithmetic, ==0 if neutral.
        //
        int8_t hint_bitwise;

        // Whether it expects signed operands or not.
        //
        int8_t is_signed;

        // Number of operands it takes. Either 1 or 2.
        //
        size_t operand_count;

        // Whether the operation is commutative or not.
        //
        bool is_commutative;

        // Symbol of the operation.
        //
        const char* symbol;

        // Name of the function associated with the operation.
        //
        const char* function_name;

        // Operator used to self-join by. 
        // - For instance ::add for ::add since (A+B)+C would 
        //   join RHS of (A+B) with RHS of (...)+C by ::add.
        //
        operator_id join_by = operator_id::invalid;

        // Creates a string representation based on the operands passed.
        //
        inline std::string to_string( const std::string& lhs, const std::string& rhs ) const
        {
            // If unary function:
            //
            if ( operand_count == 1 )
            {
                // If it has a symbol, use it, else return in function format.
                //
                if ( symbol ) return symbol + rhs;
                else          return format::str( "%s(%s)", function_name, lhs, rhs );
            }
            // If binary function:
            //
            else if ( operand_count == 2 )
            {
                // If it has a symbol, use it, else return in function format.
                //
                if ( symbol ) return format::str( "(%s%s%s)", lhs, symbol, rhs );
                else          return format::str( "%s(%s, %s)", function_name, lhs, rhs );
            }
            unreachable();
        }
    };
    static constexpr operator_desc descriptors[] = 
    {
        // Skipping ::invalid.
        {},

        /*  [Bitwise]   [Signed]  [#Op] [Commutative]   [Symbol]    [Name]         [Join by]              */
        {   +1,       false,    1,    false,          "~",        "not"                                   },
        {   +1,       false,    2,    true,           "&",        "and",         operator_id::bitwise_and },
        {   +1,       false,    2,    true,           "|",        "or",          operator_id::bitwise_or  },
        {   +1,       false,    2,    true,           "^",        "xor",         operator_id::bitwise_xor },
        {   +1,       false,    2,    false,          ">>",       "shr",         operator_id::add         },
        {   +1,       false,    2,    false,          "<<",       "shl",         operator_id::add         },
        {   +1,       false,    2,    false,          ">]",       "rotr",        operator_id::add         },
        {   +1,       false,    2,    false,          "[<",       "rotl",        operator_id::add         },
        {   -1,       true,     1,    false,          "-",        "neg"                                   },
        {   -1,       true,     2,    true,           "+",        "add",         operator_id::add         },
        {   -1,       true,     2,    false,          "-",        "sub",         operator_id::add         },
        {   -1,       true,     2,    true,           "h*",       "mulhi"                                 },
        {   -1,       true,     2,    true,           "*",        "mul",         operator_id::multiply    },
        {   -1,       true,     2,    false,          "/",        "div",         operator_id::multiply    },
        {   -1,       true,     2,    false,          "%",        "rem"                                   },
        {   -1,       false,    2,    true,           "uh*",      "umulhi"                                },
        {   -1,       false,    2,    true,           "u*",       "umul",        operator_id::umultiply   },
        {   -1,       false,    2,    false,          "u/",       "udiv",        operator_id::umultiply   },
        {   -1,       false,    2,    false,          "u%",       "urem"                                  },
        {    0,       false,    2,    false,          nullptr,    "__zx"                                  },
        {   -1,       true,     2,    false,          nullptr,    "__sx"                                  },
        {   +1,       false,    1,    false,          nullptr,    "__popcnt"                              },
        {   +1,       false,    2,    false,          nullptr,    "__msb"                                 },
        {   +1,       false,    2,    false,          nullptr,    "__lsb"                                 },
        {   +1,       false,    2,    false,          nullptr,    "__bt"                                  },
        {   +1,       false,    1,    false,          nullptr,    "__mask"                                },
        {   +1,       false,    1,    false,          nullptr,    "__bitcnt"                              },
        {    0,       false,    2,    false,          "?",        "if"                                    },
        {    0,       false,    2,    false,          nullptr,    "max",        operator_id::max_value    },
        {    0,       false,    2,    false,          nullptr,    "min",        operator_id::min_value    },
        {    0,       false,    2,    false,          nullptr,    "max_sgn",    operator_id::smax_value   },
        {    0,       false,    2,    false,          nullptr,    "min_sgn",    operator_id::smin_value   },
        {   -1,       false,    2,    false,          ">",        "greater"                               },
        {   -1,       false,    2,    false,          ">=",       "greater_eq"                            },
        {    0,       false,    2,    false,          "==",       "equal"                                 },
        {    0,       false,    2,    false,          "!=",       "not_equal"                             },
        {   -1,       false,    2,    false,          "<=",       "less_eq"                               },
        {   -1,       false,    2,    false,          "<",        "less"                                  },
        {    0,       false,    2,    false,          "u>",       "ugreater"                              },
        {    0,       false,    2,    false,          "u>=",      "ugreater_eq"                           },
        {    0,       false,    2,    false,          "u<=",      "uless_eq"                              },
        {    0,       false,    2,    false,          "u<",       "uless"                                 },
    };
    inline static const operator_desc* descriptor_of( operator_id id ) { return ( operator_id::invalid < id && id < operator_id::max ) ? &descriptors[ ( size_t ) id ] : nullptr; }

    // Evaluates the operator, on LHS and RHS. 
    // - If unary LHS is ignored.
    //
    static uint64_t evaluate( operator_id id, uint8_t bcnt, uint64_t lhs, uint64_t rhs )
    {
        // Normalize the input.
        //
        if ( bcnt != 64 )
        {
            if ( descriptor_of( id )->is_signed )
                lhs = math::sign_extend( lhs, bcnt ), rhs = math::sign_extend( rhs, bcnt );
            else
                lhs = math::zero_extend( lhs, bcnt ), rhs = math::zero_extend( rhs, bcnt );
        }

        // Create aliases for signed values to avoid ugly casts.
        //
        int64_t& ilhs = ( int64_t& ) lhs;
        int64_t& irhs = ( int64_t& ) rhs;

        // Calculate the result of the operation.
        //
        uint64_t result = 0;
        switch ( id )
        {
            // - Bitwise operators.
            //
            case operator_id::bitwise_not:      result = ~rhs;                                                      break;
            case operator_id::bitwise_and:      result = lhs & rhs;                                                 break;
            case operator_id::bitwise_or:       result = lhs | rhs;                                                 break;
            case operator_id::bitwise_xor:      result = lhs ^ rhs;                                                 break;
            case operator_id::shift_right:      result = rhs >= bcnt ? 0 : lhs >> rhs;                              break;
            case operator_id::shift_left:       result = rhs >= bcnt ? 0 : lhs << rhs;                              break;
            case operator_id::rotate_right:     result = ( lhs >> ( rhs % bcnt ) )
                                                        | ( lhs << ( bcnt - ( rhs % bcnt ) ) );                     break;
            case operator_id::rotate_left:      result = ( lhs << ( rhs % bcnt ) )
                                                        | ( lhs >> ( bcnt - ( rhs % bcnt ) ) );                     break;
            // - Arithmetic operators.										                  
            //																                  
            case operator_id::negate:           result = -irhs;                                                     break;
            case operator_id::add:              result = ilhs + irhs;                                               break;
            case operator_id::substract:        result = ilhs - irhs;                                               break;
            case operator_id::multiply_high:    result = bcnt == 64
                                                        ? __mulh( ilhs, irhs )
                                                        : uint64_t( ilhs * irhs ) >> bcnt;                          break;
            case operator_id::umultiply_high:   result = bcnt == 64
                                                        ? __umulh( lhs, rhs )
                                                        : ( lhs * rhs ) >> bcnt;                                    break;
            case operator_id::multiply:         result = ilhs * irhs;                                               break;
            case operator_id::umultiply:        result = lhs * rhs;                                                 break;
            case operator_id::divide:           result = ilhs / irhs;                                               break;
            case operator_id::udivide:	        result = lhs / rhs;                                                 break;
            case operator_id::remainder:        result = ilhs % irhs;                                               break;
            case operator_id::uremainder:	    result = lhs % rhs;                                                 break;

            // - Special operators.										                  
            //																                  
            case operator_id::sign_extend:      result = ilhs, bcnt = rhs;                                          break;
            case operator_id::zero_extend:      result = lhs,  bcnt = rhs;                                          break;
            case operator_id::popcnt:           result = __popcnt64( rhs );                                         break;
            case operator_id::most_sig_bit:	    result = _BitScanReverse64( ( unsigned long* ) &result, lhs )
                                                        ? result
                                                        : rhs;													    break;
            case operator_id::least_sig_bit:	result = _BitScanForward64( ( unsigned long* ) &result, lhs )
                                                        ? result
                                                        : rhs;													    break;
            case operator_id::bit_test:	        result = ( lhs >> rhs ) & 1;                                        break;
            case operator_id::mask:	            result = mask( bcnt );												break;
            case operator_id::bitcnt:           result = bcnt;                                                      break;
            case operator_id::value_if:         result = ( lhs & 1 ) ? rhs : 0;                                     break;

            // - Comparison operators
            //
            case operator_id::greater:          result = ilhs > irhs;                                               break;
            case operator_id::greater_eq:       result = ilhs >= irhs;                                              break;
            case operator_id::equal:            result = lhs == rhs;                                                break;
            case operator_id::not_equal:        result = lhs != rhs;                                                break;
            case operator_id::less_eq:          result = ilhs <= irhs;                                              break;
            case operator_id::less:	            result = ilhs < irhs;                                               break;
            case operator_id::ugreater:         result = lhs > rhs;                                                 break;
            case operator_id::ugreater_eq:      result = lhs >= rhs;                                                break;
            case operator_id::uless_eq:         result = lhs <= rhs;                                                break;
            case operator_id::uless:	        result = lhs < rhs;                                                 break;
            default:                            unreachable();
        }

        // Mask and return.
        //
        result &= math::mask( bcnt );
        return result;
    }
};