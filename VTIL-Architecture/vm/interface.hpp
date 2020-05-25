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
#include "../routine/basic_block.hpp"

namespace vtil
{
	// Describes each reason virtual machine could have exited because of,
	// also acts as a bitmask to suppress exits at ::run.
	//
	enum vmexit_mask : uint32_t
	{
		// Mask to supress all possible exits apart from halt.
		//
		vmexit_supress_all =         0,
	  
		// Indicates that VM was exited because it halted,
		// cannot be masked off.
		//
		vmexit_halt =                0,
		
		// Exits on undefined operations that cannot be executed.
		//
		vmexit_undefined =           1 << 0,

		// Exits on volatile instructions.
		//
		vmexit_volatile =            1 << 1,

		// Exits when a volatile register is being accessed.
		//
		vmexit_volatile_register =   1 << 2,

		// Exits when a volatile memory is being accessed.
		//
		vmexit_volatile_memory =     1 << 3,
	};

	// Basic virtual machine interface.
	//
	struct vm_interface
	{
		// Reads from the register.
		//
		virtual symbolic::expression read_register( const register_desc& desc ) = 0;
		
		// Reads the given number of bytes from the memory.
		//
		virtual symbolic::expression read_memory( const symbolic::expression& pointer, size_t byte_count ) = 0;

		// Writes to the register.
		//
		virtual void write_register( const register_desc& desc, symbolic::expression value ) = 0;
		
		// Writes the given expression to the memory.
		//
		virtual void write_memory( const symbolic::expression& pointer, symbolic::expression value ) = 0;

		// Runs the given instruction, returns whether it was successful.
		//
		virtual bool execute( const instruction& ins );

		// Given an iterator from a basic block, runs until the end of the block is reached. 
		// If an unknown instruction is hit, breaks the loop if specified so, ignores it and
		// sets the affected registers and memory undefined instead otherwise.
		//
		std::pair<il_const_iterator, vmexit_mask> run( il_const_iterator it, uint32_t exit_mask = vmexit_supress_all );
	};
};