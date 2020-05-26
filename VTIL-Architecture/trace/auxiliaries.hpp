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
#include <vtil/symex>
#include "tracer.hpp"
#include "../routine/basic_block.hpp"
#include "../symex/variable.hpp"

namespace vtil
{
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

    // Checks if the instruction given accesses the variable, optionally filtering to the
    // access type specified, tracer passed will be used to generate pointers when needed.
    //
    access_details test_access( const il_const_iterator& it,
                                const symbolic::variable::descriptor_t& var,
                                tracer* tracer, access_type type = access_type::none );
};