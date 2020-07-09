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
#include <string>
#include <functional>
#include <algorithm>
#include "bitwise.hpp"

namespace vtil::math
{
    enum class operator_id : uint8_t
    {
        invalid,        // = <Invalid>

        // ------------------ Bitwise Operators ------------------ //

        // Bitwise modifiers:
        //
        bitwise_not,    // ~RHS

        // Basic bitwise operations:
        //
        bitwise_and,    // LHS&(RHS&...)
        bitwise_or,     // LHS|(RHS|...)
        bitwise_xor,    // LHS^(RHS^...)

        // Distributing bitwise operations:
        //
        shift_right,    // LHS>>(RHS+...)
        shift_left,     // LHS<<(RHS+...)
        rotate_right,   // LHS>](RHS+...)
        rotate_left,    // LHS[<(RHS+...)

        // ---------------- Arithmetic Operators ----------------- //

        // Arithmetic modifiers:
        //
        negate,         // -RHS

        // Basic arithmetic operations:
        //
        add,            // LHS+(RHS+...)
        subtract,       // LHS-(RHS+...)

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
        ucast,          // uintRHS_t(LHS)
        cast,           // intRHS_t(LHS)
        popcnt,         // POPCNT(RHS)
        bitscan_fwd,    // BitScanForward(RHS)
        bitscan_rev,    // BitScanReverse(RHS)
        bit_test,       // [LHS>>RHS]&1
        mask,           // RHS.mask()
        bit_count,      // RHS.bitcount()
        value_if,       // LHS&1 ? RHS : 0

        max_value,      // LHS>=RHS ? LHS : RHS
        min_value,      // LHS<=RHS ? LHS : RHS

        umax_value,     // < Unsigned variants of above >
        umin_value,     //

        greater,        // LHS > RHS
        greater_eq,     // LHS >= RHS
        equal,          // LHS == RHS
        not_equal,      // LHS != RHS
        less_eq,        // LHS <= RHS
        less,           // LHS < RHS
                  
        ugreater,       // < Unsigned variants of above > [Note: equal and not_equal are always unsigned.]
        ugreater_eq,    //
        uequal,         //
        unot_equal,     //
        uless_eq,       //
        uless,          //
    max,
    };

    // Basic properties of each operator.
    //
    struct operator_desc
    {
        // >0 if bitwise operations are preferred as operands, <0 if arithmetic, ==0 if neutral.
        //
        int hint_bitwise;

        // Whether it expects signed operands or not.
        //
        bool is_signed;

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

        // Coefficient of the expression complexity, will be multiplied with an additional x2 
        // in case bitwise/aritmethic mismatch is hit within child expressions.
        //
        double complexity_coeff;

        // Creates a string representation based on the operands passed.
        //
        std::string to_string( const std::string& lhs, const std::string& rhs ) const
        {
            // If unary function:
            //
            if ( operand_count == 1 )
            {
                // If it has a symbol, use it, else return in function format.
                //
                if ( symbol ) return symbol + rhs;
                else          return format::str( "%s(%s)", function_name, rhs );
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

        /*  [Bitwise] [Signed]  [#Op] [Commutative]   [Symbol]    [Name]         [Cost] */
        {   +1,       false,    1,    false,          "~",        "not",         1      },
        {   +1,       false,    2,    true,           "&",        "and",         1      },
        {   +1,       false,    2,    true,           "|",        "or",          1      },
        {   +1,       false,    2,    true,           "^",        "xor",         1      },
        {   +1,       false,    2,    false,          ">>",       "shr",         1.5    },
        {   +1,       false,    2,    false,          "<<",       "shl",         1.5    },
        {   +1,       false,    2,    false,          ">]",       "rotr",        0.5    },
        {   +1,       false,    2,    false,          "[<",       "rotl",        0.5    },
        {   -1,       true,     1,    false,          "-",        "neg",         1      },
        {   -1,       true,     2,    true,           "+",        "add",         1      },
        {   -1,       true,     2,    false,          "-",        "sub",         1      },
        {   -1,       true,     2,    true,           "h*",       "mulhi",       1.3    },
        {   -1,       true,     2,    true,           "*",        "mul",         1.3    },
        {   -1,       true,     2,    false,          "/",        "div",         1.3    },
        {   -1,       true,     2,    false,          "%",        "rem",         1.3    },
        {   -1,       false,    2,    true,           "uh*",      "umulhi",      1.3    },
        {   -1,       false,    2,    true,           "u*",       "umul",        1.3    },
        {   -1,       false,    2,    false,          "u/",       "udiv",        1.3    },
        {   -1,       false,    2,    false,          "u%",       "urem",        1.3    },
        {    0,       false,    2,    false,          nullptr,    "__ucast",     1      },
        {   -1,       true,     2,    false,          nullptr,    "__cast",      1      },
        {   +1,       false,    1,    false,          nullptr,    "__popcnt",    1      },
        {   +1,       false,    1,    false,          nullptr,    "__bsf",       1      },
        {   +1,       false,    1,    false,          nullptr,    "__bsr",       1      },
        {   +1,       false,    2,    false,          nullptr,    "__bt",        1      },
        {   +1,       false,    1,    false,          nullptr,    "__mask",      1      },
        {    0,       false,    1,    false,          nullptr,    "__bcnt",      1      },
        {    0,       false,    2,    false,          "?",        "if",          1      },
        {    0,       false,    2,    true,           nullptr,    "max",         1      },
        {    0,       false,    2,    true,           nullptr,    "min",         1      },
        {    0,       true,     2,    true,           nullptr,    "umax",        1      },
        {    0,       true,     2,    true,           nullptr,    "umin",        1      },
        {   -1,       true,     2,    false,          ">",        "greater",     1      },
        {   -1,       true,     2,    false,          ">=",       "greater_eq",  1.2    },
        {    0,       false,    2,    true,           "==",       "equal",       1      },
        {    0,       false,    2,    true,           "!=",       "not_equal",   1      },
        {   -1,       true,     2,    false,          "<=",       "less_eq",     1.2    },
        {   -1,       true,     2,    false,          "<",        "less",        1      },
        {   +1,       false,    2,    false,          "u>",       "ugreater",    1      },
        {   +1,       false,    2,    false,          "u>=",      "ugreater_eq", 1.2    },
        {    0,       false,    2,    true,           "u==",      "uequal",      1      },
        {    0,       false,    2,    true,           "u!=",      "unot_equal",  1      },
        {   +1,       false,    2,    false,          "u<=",      "uless_eq",    1.2    },
        {   +1,       false,    2,    false,          "u<",       "uless",       1      },
    };
    static_assert( std::size( descriptors ) == size_t( operator_id::max ), "Operator descriptor table is invalid." );
    static constexpr const operator_desc* descriptor_of( operator_id id ) 
    { 
        return ( operator_id::invalid < id && id < operator_id::max ) ? &descriptors[ ( size_t ) id ] : nullptr; 
    }

    // Operators that return bit-indices, always use the following size.
    //
    static constexpr bitcnt_t bit_index_size = 8;

    // Calculates the size of the result after after the application of the operator [id] on the operands.
    //
    bitcnt_t result_size( operator_id id, bitcnt_t bcnt_lhs, bitcnt_t bcnt_rhs );

    // Applies the specified operator [id] on left hand side [lhs] and right hand side [rhs]
    // and returns the output as a masked unsigned 64-bit integer <0> and the final size <1>.
    //
    std::pair<uint64_t, bitcnt_t> evaluate( operator_id id, bitcnt_t bcnt_lhs, uint64_t lhs, bitcnt_t bcnt_rhs, uint64_t rhs );

    // Applies the specified operator [op] on left hand side [lhs] and right hand side [rhs] wher
    // input and output values are expressed in the format of bit-vectors with optional unknowns,
    // and no size constraints.
    //
    bit_vector evaluate_partial( operator_id op, const bit_vector& lhs, const bit_vector& rhs );
};