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
#include <vtil/amd64>
#include "control_registers.hpp"

namespace vtil::arch
{
	// Register descriptors are used to describe each unique "full" register such as RAX. 
	// Any physical register such as EAX will be extended to its full form (RAX in this case).
	// - Note: Size of a register is always assumed to be 64-bits.
	//
	struct register_desc
	{
		// Descriptor's identifier will be used for comparison if the register 
		// instance is not mapped to any physical register.
		//
		std::string identifier = "";

		// If this field is not X86_REG_INVALID, it's an indicator that this
		// register and the alias essentially maps to a physical register.
		//
		x86_reg maps_to = X86_REG_INVALID;

		// Either a x86 register identifier or an arbitrary string must be passed
		// to construct a register descriptor.
		//
		register_desc() = default;
		register_desc( x86_reg reg ) 
		{ 
			maps_to = reg >= X86_REG_VCR0 ? reg : amd64::extend( reg );
			identifier = reg >= X86_REG_VCR0 ? lookup_control_register( reg )->identifier : amd64::name( maps_to );
		}
		register_desc( const std::string& id ) : identifier( id ) {}

		// Conversion to human-readable format.
		//
		std::string to_string() const { return identifier; }

		// Simple helpers to determine the type of register.
		//
		bool is_physical() const { return maps_to != X86_REG_INVALID; }
		bool is_valid() const { return !identifier.empty(); }

		// Basic comparison operators.
		//
		bool operator!=( const register_desc& o ) const { return !operator==( o ); }
		bool operator==( const register_desc& o ) const { return identifier == o.identifier; }
		bool operator<( const register_desc& o ) const { return identifier < o.identifier; }
	};
};