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
#include <vtil/utility>
#include "interface.hpp"
#include "../symex/memory.hpp"
#include "../symex/context.hpp"

namespace vtil
{
	// A virtual machine implementation that executes in terms of symbolic expressions.
	//
	struct symbolic_vm : vm_interface
	{
		// State of the virtual machine.
		//
		symbolic::memory memory_state;
		symbolic::context register_state;

		// Configuration of the virtual machine.
		//
		bool is_lazy = false;
		il_const_iterator reference_iterator = symbolic::free_form_iterator;

		// Reads from the register.
		//
		symbolic::expression::reference read_register( const register_desc& desc ) override 
		{ 
			return register_state.read( desc, reference_iterator ); 
		}

		// Writes to the register.
		//
		void write_register( const register_desc& desc, symbolic::expression::reference value ) override 
		{ 
			if ( is_lazy ) value.make_lazy();
			register_state.write( desc, std::move( value ) );
		}

		// Reads the given number of bytes from the memory.
		//
		symbolic::expression::reference read_memory( const symbolic::expression::reference& pointer, size_t byte_count ) override
		{
			return memory_state.read( pointer, math::narrow_cast<bitcnt_t>( byte_count * 8 ), reference_iterator );
		}
		
		// Writes the given expression to the memory.
		//
		bool write_memory( const symbolic::expression::reference& pointer, deferred_value<symbolic::expression::reference> value, bitcnt_t size ) override
		{
			if ( is_lazy )
			{
				deferred_result value_n = [ & ]() -> auto { return value.get().make_lazy(); };
				return memory_state.write( pointer, value_n, size ).has_value();
			}
			else
			{
				return memory_state.write( pointer, value, size ).has_value();
			}
		}

		// Resets the virtual machine state.
		//
		void reset() 
		{
			memory_state.reset(); 
			register_state.reset(); 
		}
	};
};