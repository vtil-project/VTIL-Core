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
#include <vtil/symex>
#include "../routine/basic_block.hpp"

namespace vtil
{
	// List of reasons that might cause the virtual machine to exit.
	//
	enum class vm_exit_reason : uint8_t
	{
		none =                0,
		stream_end =          0,
		alias_failure =       1,
		high_arithmetic =     2,
		unknown_instruction = 3
	};

	// Basic virtual machine interface.
	//
	struct vm_interface
	{
		// Reads from the register.
		//
		virtual symbolic::expression::reference read_register( const register_desc& desc ) const { unreachable(); return {}; }
		
		// Reads the given number of bytes from the memory, returns null if aliasing fails.
		//
		virtual symbolic::expression::reference read_memory( const symbolic::expression::reference& pointer, size_t byte_count ) const { unreachable(); return {}; }

		// Writes to the register.
		//
		virtual void write_register( const register_desc& desc,symbolic::expression::reference value ) { unreachable(); }
		
		// Writes the given expression to the memory, returns false if aliasing fails.
		//
		virtual bool write_memory( const symbolic::expression::reference& pointer, deferred_value<symbolic::expression::reference> value, bitcnt_t size ) { unreachable(); return false; }
		bool write_memory_v( const symbolic::expression::reference& pointer, symbolic::expression::reference value ) { return write_memory( pointer, std::move( value ), value.size() ); }

		// Runs the given instruction, returns whether it was successful.
		//
		virtual vm_exit_reason execute( const instruction& ins );

		// Given an iterator from a basic block, executes every instruction until the end of the block 
		// is reached. If it exits due to any reason, returns the reason, otherwise ::none.
		//
		std::pair<il_const_iterator, vm_exit_reason> run( il_const_iterator it );
	};
};