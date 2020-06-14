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
	// Basic virtual machine interface.
	//
	struct vm_interface
	{
		// Returns the full register size for the given descriptor.
		//
		virtual bitcnt_t size_register( const register_desc& desc ) { return 64; }

		// Reads from the register.
		//
		virtual symbolic::expression read_register( const register_desc& desc ) { unreachable(); return {}; }
		
		// Reads the given number of bytes from the memory.
		//
		virtual symbolic::expression read_memory( const symbolic::expression& pointer, size_t byte_count ) { unreachable(); return {}; }

		// Writes to the register.
		//
		virtual void write_register( const register_desc& desc, symbolic::expression value ) { unreachable(); }
		
		// Writes the given expression to the memory.
		//
		virtual void write_memory( const symbolic::expression& pointer, symbolic::expression value ) { unreachable(); }

		// Runs the given instruction, returns whether it was successful.
		//
		virtual bool execute( const instruction& ins );

		// Given an iterator from a basic block, executes every instruction until the end of the block 
		// is reached. If an unknown instruction is hit, breaks out of the loop if specified so, otherwise
		// ignores it setting the affected registers and memory to undefined values.
		//
		il_const_iterator run( il_const_iterator it, bool exit_on_ud = true );
	};
};