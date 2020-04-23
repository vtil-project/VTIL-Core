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
#include <string>
#include <vector>
#include <vtil/io>
#include <vtil/math>
#include "operands.hpp"

namespace vtil
{
    // Maximum operand count.
    //
    static constexpr size_t max_operand_count = 4;

    // Describes the way an instruction acceses it's operands and the
    // constraints built around that, such as "immediate only" implied 
    // by the "_imm" suffix.
    //
    enum class operand_access : uint8_t
    {
        // Note: 
        // It still is valid to do != write for read and >= write for writes.
        // this operand access type is illegal to use outside of function arguments.
        //
        invalid = 0, 

        // Read group:
        //
        read_imm,
        read_reg,
        read_any,
        read = read_any,

        // Write group: 
        // - Implicit "_reg" as we cannot write into an immediate
        //
        write,
        readwrite
    };
    
    // Instruction descriptors are used to describe each unique instruction 
    // in the VTIL instruction set. This type should be only constructed 
    // as a global constant. For the sake of consistency all operand indices
    // passed to the constructor start from 1. [Ref: branch_operands desc.]
    //
    struct instruction_desc
    {
        // Name of the instruction.
        //
        std::string name;

        // List of the access types for each operand.
        //
        std::vector<operand_access> access_types;

        // Index of the operand that determines the instruction's 
        // access size property.
        //
        int access_size_index = 0;

        // Whether the instruction is volatile or not meaning it
        // should not be discarded even if it is no-op or dead.
        //
        bool is_volatile = false;

        // A pointer to the expression operator that describes the
        // operation of this instruction if applicable.
        //
        math::operator_id symbolic_operator = math::operator_id::invalid;

        // List of operands that are thread as branching destinations.
        // - In the constructor version negative indices are used to 
        //   indicate "real" destinations and thus for the sake of 
        //   simplicity indices start from 1.
        //
        std::vector<int> branch_operands_rip = {};
        std::vector<int> branch_operands_vip = {};

        // Operand that marks the beginning of a memory reference and whether
        // it writes to the pointer or not. [Idx] must be a register and [Idx+1]
        // must be an immediate.
        //
        int memory_operand_index = -1;
        bool memory_write = false;

        // Generic data-assignment constructor with certain validity checks.
        //
        instruction_desc( const std::string& name,
                          const std::vector<operand_access>& access_types,
                          int access_size_index,
                          bool is_volatile,
                          math::operator_id symbolic_operator,
                          std::vector<int> branch_operands,
                          const std::pair<int, bool>& memory_operands );

        // Number of operands this instruction has.
        //
        size_t operand_count() const { return access_types.size(); }

        // Whether the instruction branches for not.
        //
        bool is_branching_virt() const { return !branch_operands_vip.empty(); }
        bool is_branching_real() const { return !branch_operands_rip.empty(); }
        bool is_branching() const { return is_branching_virt() || is_branching_real(); }

        // Whether the instruction acceses/reads/writes memory or not.
        //
        bool reads_memory() const { return accesses_memory() && !memory_write; }
        bool writes_memory() const { return accesses_memory() && memory_write; }
        bool accesses_memory() const { return memory_operand_index != -1; }

        // Conversion to human-readable format.
        //
	    std::string to_string( uint8_t access_size ) const
	    {
		    if ( !access_size ) return name;
            fassert( ( access_size % 8 ) == 0 );
		    return name + ( char ) format::suffix_map[ access_size / 8 ];
	    }

        // Redirect basic comparison operators to the name of the instruction.
        //
        bool operator!=( const instruction_desc& o ) const { return name != o.name; }
        bool operator==( const instruction_desc& o ) const { return name == o.name; }
        bool operator<( const instruction_desc& o ) const { return name < o.name; }
    };
};