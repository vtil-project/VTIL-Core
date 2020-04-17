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
#include "register_view.hpp"

// Any operand used in a VTIL instruction will be essentialy either a register or an 
// immediate value, where registers can also be either temporaries, physical registers or 
// control registers.
//
//  - 1) Immediate value
//  - 2) Register
//	  - a) Temporaries
//	  - b) Physical registers
//	  - c) Control registers
//
namespace vtil::arch
{
	// The operand structure that is used to describe operands of an instruction.
	//
	struct operand
	{
		// If operand is a register:
		//
		register_view reg = {};

		// If operand is an immediate:
		//
		union
		{
			uint64_t u64 = 0;
			int64_t i64;
		};
		uint8_t imm_size = 0;

		// Operand type is constructed either by a register view or an immediate
		// followed by an explicit size.
		//
		operand() = default;
		operand( const register_view& rw ) : reg( rw ), imm_size( 0 ) {}
		operand( uint64_t v, uint8_t size ) : u64( v ), imm_size( size ) {}

		// Getter for the operand size.
		//
		uint8_t size() const { return is_immediate() ? imm_size : reg.size; }

		// Conversion to human-readable format.
		//
		std::string to_string() const { return is_register() ? reg.to_string() : format::hex( i64 ); }

		// Simple helpers to determine the type of operand.
		//
		bool is_register() const { return reg.is_valid(); }
		bool is_immediate() const { return imm_size != 0; }
		bool is_valid() const { return is_register() || is_immediate(); }

		// Basic comparison operators.
		//
		bool operator!=( const operand& o ) const { return !operator==( o ); };
		bool operator==( const operand& o ) const { return is_register() ? reg == o.reg : imm_size == o.imm_size && u64 == o.u64; }
		bool operator<( const operand& o ) const { return is_register() ? reg < o.reg : ( imm_size == o.imm_size ? u64 < o.u64 : imm_size < o.imm_size ); }
	};
};