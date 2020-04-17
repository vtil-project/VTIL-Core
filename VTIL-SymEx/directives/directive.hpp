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

namespace vtil::symbolic
{
    // Custom operators to be used within simplifier directives.
    //
    static constexpr math::operator_id simplify_dir = ( math::operator_id )( ( size_t ) math::operator_id::max + 1 );
    static constexpr math::operator_id unpack_dir = ( math::operator_id )( ( size_t ) simplify_dir + 1 );
    static constexpr math::operator_id iff_dir = ( math::operator_id )( ( size_t ) unpack_dir + 1 );
    static constexpr math::operator_id or_dir = ( math::operator_id )( ( size_t ) iff_dir + 1 );

    // Used to describe a simplifier directive.
    //
    struct directive : math::operable<directive>
    {
        // Internal representation of the operation.
        //
        const char* id = nullptr;
        math::operator_id op = math::operator_id::invalid;
        shared_reference<directive> lhs;
        shared_reference<directive> rhs;

        // Default/copy/move constructors.
        //
        directive() {};
        directive( directive&& ) = default;
        directive( const directive& ) = default;
        directive& operator=( directive&& o ) = default;
        directive& operator=( const directive& o ) = default;

        // Variable constructor.
        //
        directive( const char* id ) : id( id ) {}
        directive( int64_t v ) : operable( v ) {}

        // Constructor for directive representing the result of an unary operator.
        //
        directive( math::operator_id _op, const directive& e1 );

        // Constructor for directive representing the result of a binary operator.
        //
        directive( const directive& e1, math::operator_id _op, const directive& e2 );

        // Converts to human-readable format.
        //
        std::string to_string() const;

        // Simple equivalence check.
        //
        bool equals( const directive& o ) const;
    };

    // Implement custom operators.
    //
    static directive operator!( const directive& a ) { return { simplify_dir, a }; }
    static directive __unpack( const directive& a, const directive& b ) { return { a, unpack_dir, b }; }
    static directive __iff( const directive& a, const directive& b ) { return { a, iff_dir, b }; }
    static directive __or( const directive& a, const directive& b ) { return { a, or_dir, b }; }
};