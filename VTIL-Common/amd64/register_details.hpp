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

// Furthermore, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information                   |
// |-------------------------|------------------------------------------------|
// | amd64/*                 | https://github.com/aquynh/capstone/            |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#pragma once
#include <map>
#include <tuple>
#include <string>
#include "disassembler.hpp"
#include "../io/asserts.hpp"

namespace vtil::amd64
{
	// Structure describing how a register maps to another register.
	//
	struct register_mapping
	{
		// Base register of full size, e.g. X86_REG_RAX.
		//
		x86_reg base_register;
		
		// Offset of the current register from the base register.
		//
		uint8_t offset;

		// Size of the current register in bytes.
		//
		uint8_t size;

		// Cast to tuple for structured binding.
		//
		operator std::tuple<x86_reg, uint8_t, uint8_t>() { return { base_register, offset, size }; }
	};

	// Gets the offset<0> and size<1> of the mapping for the given register.
	//
	register_mapping resolve_mapping( uint8_t _reg );
	
	// Gets the base register for the given register.
	//
	x86_reg extend( uint8_t _reg );

	// Converts the enum into human-readable format.
	//
	std::string name( uint8_t _reg );

	// Remaps the given register at given specifications.
	//
	x86_reg remap( uint8_t _reg, uint8_t offset, uint8_t size );
};