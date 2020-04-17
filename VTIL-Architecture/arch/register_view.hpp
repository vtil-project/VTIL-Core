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
#include "control_registers.hpp"
#include "register_descriptor.hpp"

namespace vtil::arch
{
	// Register views are used to describe well-defined segments of registers.
	// - AX views RAX @ {0, 2}, BH views RBX @ {1, 1} so on. 
	//
	struct register_view
	{
		// The base register descriptor.
		//
		register_desc base = {};

		// Offset into that register and the segment referenced.
		//
		uint8_t offset = 0;
		uint8_t size = 8;

		// Basically an extended version of the register descriptor constructor
		// with the addition of an offset and a size value.
		//
		register_view() = default;
		register_view( x86_reg base, uint8_t offset = 0, uint8_t size = 8 );
		register_view( const std::string& base, uint8_t offset = 0, uint8_t size = 8 );
		register_view( const register_desc& base, uint8_t offset = 0, uint8_t size = 8 );

		// Mask that describes how we map to the base register and a
		// basic "overlapping" check using this mask.
		//
		uint64_t get_mask() const { return ( ~0ull >> ( 64 - size * 8 ) ) << ( offset * 8 ); }
		bool overlaps( const register_view& o )  const { return base == o.base && ( get_mask() & o.get_mask() ); }

		// Conversion to human-readable format.
		//
		std::string to_string( bool explicit_size = false ) const;

		// Validity check.
		//
		bool is_valid() const { return base.is_valid() && ( offset + size ) <= 8; }

		// Basic comparison operators.
		//
		bool operator!=( const register_view& o ) const;
		bool operator==( const register_view& o ) const;
		bool operator<( const register_view& o ) const;
	};
};

// Testing new flags system, will remove. [TODO]
//
namespace vtil
{
	static const arch::register_view REG_UNKB = { arch::create_control_register( { "unkb", true } ), 0, 1 };
	static const arch::register_view REG_UNKW = { arch::create_control_register( { "unkw", true } ), 0, 2 };
	static const arch::register_view REG_UNKD = { arch::create_control_register( { "unkd", true } ), 0, 4 };
	static const arch::register_view REG_UNKQ = { arch::create_control_register( { "unkq", true } ), 0, 8 };
	static const arch::register_view REG_ZF =   { arch::create_control_register( { "eflags.zf", false } ), 0, 1 };
	static const arch::register_view REG_SF =   { arch::create_control_register( { "eflags.sf", false } ), 0, 1 };
	static const arch::register_view REG_PF =   { arch::create_control_register( { "eflags.pf", false } ), 0, 1 };
	static const arch::register_view REG_AF =   { arch::create_control_register( { "eflags.af", false } ), 0, 1 };
	static const arch::register_view REG_OF =   { arch::create_control_register( { "eflags.of", false } ), 0, 1 };
	static const arch::register_view REG_CF =   { arch::create_control_register( { "eflags.cf", false } ), 0, 1 };
};