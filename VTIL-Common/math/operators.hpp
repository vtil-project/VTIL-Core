#pragma once
#include <stdint.h>
#include <string>
#include <intrin.h>
#include <functional>
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
        int8_t is_signed;
        size_t operand_count;
        bool is_commutative;
        const char* symbol;
        const char* function_name;
        operator_id join_by = operator_id::invalid;
    };
    static constexpr operator_desc descriptors[] = 
    {
        // Skipping ::invalid.
        {},

        /*  [Signed]  [#Op] [Commutative]   [Symbol]    [Name]         [Join by]                */
        {   false,    1,    false,          "~",        "not"                                   },
        {   false,    2,    true,           "&",        "and",         operator_id::bitwise_and },
        {   false,    2,    true,           "|",        "or",          operator_id::bitwise_or  },
        {   false,    2,    true,           "^",        "xor",         operator_id::bitwise_xor },
        {   false,    2,    false,          ">>",       "shr",         operator_id::add         },
        {   false,    2,    false,          "<<",       "shl",         operator_id::add         },
        {   false,    2,    false,          ">]",       "rotr",        operator_id::add         },
        {   false,    2,    false,          "[<",       "rotl",        operator_id::add         },
        {   true,     2,    false,          "-",        "neg"                                   },
        {   true,     2,    true,           "+",        "add",         operator_id::add         },
        {   true,     2,    false,          "-",        "sub",         operator_id::add         },
        {   true,     2,    true,           "h*",       "mulhi"                                 },
        {   true,     2,    true,           "*",        "mul",         operator_id::multiply    },
        {   true,     2,    false,          "/",        "div",         operator_id::multiply    },
        {   true,     2,    false,          "%",        "rem"                                   },
        {   false,    2,    true,           "uh*",      "umulhi"                                },
        {   false,    2,    true,           "u*",       "umul",        operator_id::umultiply   },
        {   false,    2,    false,          "u/",       "udiv",        operator_id::umultiply   },
        {   false,    2,    false,          "u%",       "urem"                                  },
        {   false,    2,    false,          nullptr,    "zx"                                    },
        {   false,    2,    false,          nullptr,    "sx"                                    },
        {   false,    1,    false,          nullptr,    "popcnt"                                },
        {   false,    1,    false,          nullptr,    "msb"                                   },
        {   false,    1,    false,          nullptr,    "lsb"                                   },
        {   false,    2,    false,          nullptr,    "bt"                                    },
        {   false,    1,    false,          nullptr,    "mask"                                  },
        {   false,    1,    false,          nullptr,    "bitcnt"                                },
        {   false,    2,    false,          "?",        "if"                                    },
        {   false,    2,    false,          ">",        "greater"                               },
        {   false,    2,    false,          ">=",       "greater_eq"                            },
        {   false,    2,    false,          "==",       "equal"                                 },
        {   false,    2,    false,          "!=",       "not_equal"                             },
        {   false,    2,    false,          "<=",       "less_eq"                               },
        {   false,    2,    false,          "<",        "less"                                  },
        {   false,    2,    false,          "u>",       "ugreater"                              },
        {   false,    2,    false,          "u>=",      "ugreater_eq"                           },
        {   false,    2,    false,          "u<=",      "uless_eq"                              },
        {   false,    2,    false,          "u<",       "uless"                                 },
    };
    inline static const operator_desc& descriptor( operator_id id ) { return descriptors[ ( size_t ) id ]; }

    // Evaluates the operator, on LHS and RHS. 
    // - If unary LHS is ignored.
    //
    inline static uint64_t evaluate( operator_id id, uint8_t size, uint64_t lhs, uint64_t rhs )
    {
        // Normalize the input.
        //
        uint8_t bcnt = size * 8;
        if ( bcnt != 64 )
        {
            if ( descriptor( id ).is_signed )
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
            case operator_id::rotate_right:     result = ( lhs >> rhs )
                                                        | ( lhs << ( bcnt - rhs ) );                                break;
            case operator_id::rotate_left:      result = ( lhs << rhs )
                                                        | ( lhs >> ( bcnt - rhs ) );                                break;
            // - Arithmetic operators.										                  
            //																                  
            case operator_id::negate:           result = -ilhs;                                                     break;
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
            case operator_id::sign_extend:      result = math::sign_extend( lhs, rhs );                             break;
            case operator_id::zero_extend:      result = math::zero_extend( lhs, rhs );                             break;
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