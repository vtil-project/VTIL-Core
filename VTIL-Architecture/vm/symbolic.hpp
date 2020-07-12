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
#include "interface.hpp"
#include "../symex/memory.hpp"

namespace vtil
{
	// A virtual machine implementation that executes in terms of symbolic expressions.
	//
	struct symbolic_vm : vm_interface
	{
		// Flag to make I/O lazy.
		//
		bool lazy_io = false;

		// State of the virtual machine.
		//
		symbolic::memory memory_state;
		std::map<register_desc, symbolic::expression::reference> register_state;

		// Construct from memory type, defaults to free.
		//
		symbolic_vm( symbolic::memory_type mem = symbolic::memory_type::free )
			: memory_state( symbolic::create_memory( mem ) ) {}

		// Reads from the register.
		// - Value will be unpacked.
		//
		symbolic::expression::reference read_register( const register_desc& desc ) override;

		// Writes to the register.
		//
		void write_register( const register_desc& desc, symbolic::expression::reference value ) override;

		// Reads the given number of bytes from the memory.
		//
		symbolic::expression::reference read_memory( const symbolic::expression::reference& pointer, size_t byte_count ) override;
		
		// Writes the given expression to the memory.
		//
		void write_memory( const symbolic::expression::reference& pointer, symbolic::expression::reference value ) override;

		// Override execute to enforce lazyness.
		//
		bool execute( const instruction& ins ) override;

		// Resets the virtual machine state.
		//
		void reset() { memory_state.reset(); register_state.clear(); }
	};
};