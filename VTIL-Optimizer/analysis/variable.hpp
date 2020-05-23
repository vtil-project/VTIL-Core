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
#include <variant>
#include <string>
#include <vtil/io>
#include <vtil/utility>
#include <vtil/arch>
#include <vtil/symex>

namespace vtil::optimizer
{
    // A pseudo single-static-assignment variable describing the state of a 
    // memory location or a register at a given index into the instruction stream.
    //
    struct variable : reducable<variable>
    {
        // If register type, we just need the register descriptor.
        //
        using register_t = register_desc;

        // If memory type, we need the base register, the offset into it and
        // the size of the variable we're looking up. Since memory has to be
        // addressed in bytes, size is not in number of bits.
        //
        struct memory_t : reducable<memory_t>
        {
            // Absolute pointer as calculated.
            //
            symbolic::boxed_expression::reference pointer = {};

            // Size of the variable in bits.
            //
            bitcnt_t bit_count;

            // Construct from base offset and size.
            //
            memory_t( symbolic::boxed_expression::reference pointer = {}, bitcnt_t bit_count = 0 )
                : pointer( std::move( pointer ) ), bit_count( bit_count ) {}

            // Declare reduction.
            //
            REDUCE_TO( bit_count, *pointer );
        };

        // The iterator at which this variable is read at.
        //
        il_const_iterator at = {};

        // Variant descriptor that holds either one of the variable types.
        //
        using descriptor_t = std::variant<register_t, memory_t>;
        descriptor_t descriptor;

        // Since SSA constraints are violated if the block is looping,
        // we have to add a hint to declare it branch-dependant where
        // relevant.
        //
        bool is_branch_dependant = false;

        // Default, null constructor.
        //
        variable() {}

        // Constructs by iterator and the variable descriptor itself.
        //
        variable( const il_const_iterator& it, descriptor_t desc );
        variable( const il_const_iterator& it, const register_t& desc ) 
            : variable( it, descriptor_t{ desc } ) {}
        variable( const il_const_iterator& it, const memory_t& desc )
            : variable( it, descriptor_t{ desc } ) {}

        // Returns whether the variable is valid or not.
        //
        bool is_valid() const;

        // Wrappers around std::hold_alternative for convinient type checks.
        //
        bool is_memory() const { return std::holds_alternative<memory_t>( descriptor ); }
        bool is_register() const { return std::holds_alternative<register_t>( descriptor ); }

        // Wrappers around std::get.
        //
        memory_t& mem() { return std::get<memory_t>( descriptor ); }
        const memory_t& mem() const { return std::get<memory_t>( descriptor ); }
        register_t& reg() { return std::get<register_t>( descriptor ); }
        const register_t& reg() const { return std::get<register_t>( descriptor ); }

        // Returns the size of the variable in bits.
        //
        bitcnt_t bit_count() const { return std::visit( [ ] ( auto&& desc ) { return desc.bit_count; }, descriptor ); }

        // Conversion to symbolic expression.
        //
        symbolic::expression to_expression( bool unpack = true ) const;

        // Conversion to human-readable format.
        //
        std::string to_string() const;

        // Packs all the variables in the expression where it'd be optimal.
        //
        static symbolic::expression pack_all( const symbolic::expression& exp );

        // Declare reduction.
        //
        REDUCE_TO( dereference_if( !at.is_end(), at ), at.is_valid() ? at.container->entry_vip : invalid_vip, descriptor, is_branch_dependant );
    };
};