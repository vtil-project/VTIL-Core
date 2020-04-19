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
#include <vtil/math>
#include <vtil/memory>
#include <type_traits>

namespace vtil::symbolic::directive
{
    // Custom operators to be used within simplifier directives.
    //
    // - !x, indicates that x must be simplified for this directive to be valid.
    static constexpr math::operator_id simplify_dir = ( math::operator_id )( ( size_t ) math::operator_id::max + 1 );
    //
    // - __unpack(a,b), picks a if valid, otherwise b. Only one unpack decision can be made per directive
    //   and the second unpack will use the same index as the previous one.
    static constexpr math::operator_id unpack_dir = ( math::operator_id )( ( size_t ) simplify_dir + 1 );
    //
    // - __iff(a,b), returns b if a holds, otherwise invalid.
    static constexpr math::operator_id iff_dir = ( math::operator_id )( ( size_t ) unpack_dir + 1 );
    //
    // - __or(a,b), picks a if valid, otherwise b. Similar to __unpack in that sense, but does not
    //   propagate the chosen index.
    static constexpr math::operator_id or_dir = ( math::operator_id )( ( size_t ) iff_dir + 1 );
    //
    // - __unreachable(), indicates that this directive should never be matched and if it is,
    //   simplifier logic has a bug which should be fixed, acts as a debugging/validation tool.
    static constexpr math::operator_id unreachable_dir = ( math::operator_id )( ( size_t ) or_dir + 1 );

    // Matching types of the variables:
    //
    enum matching_type
    {
        match_any,
        match_variable,
        match_constant,
        match_expression,
        match_variable_or_constant,
    };

    // Used to describe a simplifier directive.
    //
    struct instance : math::operable<instance>
    {
        using reference = shared_reference<instance>;

        // If symbolic variable, the identifier of the variable
        // and type of expressions it can match.
        //
        const char* id = nullptr;
        matching_type mtype = match_any;

        // The operation we're matching and the operands.
        //
        math::operator_id op = math::operator_id::invalid;
        reference lhs = {};
        reference rhs = {};

        // Default/copy/move constructors.
        //
        instance() {};
        instance( instance&& ) = default;
        instance( const instance& ) = default;
        instance& operator=( instance&& o ) = default;
        instance& operator=( const instance& o ) = default;

        // Variable constructor.
        //
        template<typename T = uint64_t, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        instance( T value ) : operable( int64_t( value ) ) {}
        instance( const char* id, matching_type mtype = match_any ) : id( id ), mtype( mtype ) {}

        // Constructor for directive representing the result of an unary operator.
        //
        instance( math::operator_id _op, const instance& e1 );

        // Constructor for directive representing the result of a binary operator.
        //
        instance( const instance& e1, math::operator_id _op, const instance& e2 );

        // Converts to human-readable format.
        //
        std::string to_string() const;

        // Simple equivalence check.
        //
        bool equals( const instance& o ) const;
    };

    // Implement custom operators.
    //
    static instance operator!( const instance& a ) { return { simplify_dir, a }; }
    static instance __unpack( const instance& a, const instance& b ) { return { a, unpack_dir, b }; }
    static instance __iff( const instance& a, const instance& b ) { return { a, iff_dir, b }; }
    static instance __or( const instance& a, const instance& b ) { return { a, or_dir, b }; }
    static instance __unreachable() { return { 0ull, unreachable_dir, 0ull }; }

    /*
       The encoding below must be used when saving this file:
         - Unicode (UTF-8 without signature) - Codepage 65001

       Greek letters are used in simplifier directives as opposed to latin 
       in-order to make the distinction between them painfully obvious.
       
       This really saves you from all the pain of debugging when you "leak"
       a directive variable from the routines, which is why I'm so stubborn
       on using them.


       Used names are kept track using the table below:
       -------------------------------------------------------
       | Free                                     | Used     |
       | ΑΝνΒΞξΓγΟοΔπΕΡρΖζσςΗηΤτΥυΙιΦφΚκΧχΛλΨψΜμω | ΠΣΘΩαβδε |
       -------------------------------------------------------
    */

    // Symbolic variables to be used in rule creation:
    //
    static const instance A = { "α" };
    static const instance B = { "β" };
    static const instance C = { "δ" };
    static const instance D = { "ε" };

    // Special variables, one per type:
    // 
    static const instance V = { "Π", match_variable };
    static const instance U = { "Σ", match_constant };
    static const instance X = { "Θ", match_variable_or_constant };
    static const instance Q = { "Ω", match_expression };
};