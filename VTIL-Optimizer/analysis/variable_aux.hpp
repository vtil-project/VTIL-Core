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
#include <vtil/arch>
#include <vtil/symex>
#include <vtil/io>
#include "trace.hpp"
#include "variable.hpp"

namespace vtil::optimizer
{
    // Callback typedefs.
    //
    using partial_tracer_t = std::function<symbolic::expression( bitcnt_t offset, bitcnt_t size )>;
    
    // Enumeration used to describe the type of access to a variable.
    //
    enum class access_type
    {
        none,
        read,
        write,
        readwrite
    };

    // Structure describing how an instruction accesses a variable.
    //
    struct access_details
    {
        // Type of access.
        //
        access_type type = access_type::none;
        
        // Relative offset to the variable, in bits.
        //
        bitcnt_t bit_offset;

        // Number of bits the instruction wrote at that offset.
        // - Note: Not necessarily all were overlapping with the variable.
        //
        bitcnt_t bit_count;

        // Implicit cast to bool to check if non-null access.
        //
        operator bool() const { return type != access_type::none; }

        // Simple check to determine whether the details are known or not.
        //
        bool is_unknown() const { return bit_count == -1; }
    };

    // Makes a memory variable from the given instruction's src/dst, uses the tracer
    // passed to resolve the absolute pointer.
    //
    variable reference_memory( const il_const_iterator& it,
                               const trace_function_t& tracer = [ ] ( auto x ) { return trace( x ); } );

    // Checks whether the two given pointers are restrict qualified against each other
    // meaning if the delta could not be resolved as a constant, if they are guaranteed
    // not to overlap or not.
    //
	bool is_restrict_qf_against( const symbolic::expression& ptr1, 
                                 const symbolic::expression& ptr2 );

    // Checks if the instruction given accesses the variable, optionally filtering to the
    // access type specified, tracer passed will be used to generate pointers when needed.
    //
    access_details test_access( const il_const_iterator& it,
                                const variable::descriptor_t& var,
                                access_type type = access_type::none,
                                const trace_function_t& tracer = [ ] ( auto x ) { return trace( x ); } );

    // Given a partial tracer, this routine will determine the full value of the variable
    // at the given position where a partial write was found.
    //
    symbolic::expression resolve_partial( const access_details& access,
                                          bitcnt_t bit_count,
                                          const partial_tracer_t& ptracer );
};