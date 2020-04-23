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
#include <vtil/math>
#include "register_desc.hpp"

namespace vtil
{
	// Operand structure either holds an immediate or a register.
	//
	struct operand
	{
		// If operand is a register:
		//
		register_desc reg = {};

		// If operand is an immediate:
		//
		struct
		{
			union
			{
				int64_t i64;
				uint64_t u64;
			};
			bitcnt_t bit_count = 0;
		} imm;

		// Default constructor / move / copy.
		//
		operand() = default;
		operand( operand&& ) = default;
		operand( const operand& ) = default;
		operand& operator=( operand&& ) = default;
		operand& operator=( const operand& ) = default;

		// Operand type is constructed either by a register view or an immediate
		// followed by an explicit size.
		//		
		template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, operand>, int> = 0>
		operand( T&& reg ) : reg( register_cast<std::remove_cvref_t<T>>{}( reg ) ) {}
		operand( int64_t v, bitcnt_t bit_count ) : imm( { v, bit_count } ) {}

		// Getter for the operand size.
		//
		bitcnt_t size() const { return reg.is_valid() ? reg.bit_count : imm.bit_count; }

		// Conversion to human-readable format.
		//
		std::string to_string() const { return is_register() ? reg.to_string() : format::hex( imm.i64 ); }

		// Simple helpers to determine the type of operand.
		//
		bool is_register() const { return reg.is_valid(); }
		bool is_immediate() const { return imm.bit_count != 0; }
		bool is_valid() const 
		{ 
			if ( is_register() )
			{
				if ( reg.bit_offset % 8 ) return false;
				if ( reg.bit_count != 1 && ( reg.bit_count % 8 ) ) return false;
				return true;
			}
			return is_immediate(); 
		}

		// Basic comparison operators.
		//
		bool operator!=( const operand& o ) const { return !operator==( o ); };
		bool operator==( const operand& o ) const { return is_register() ? reg == o.reg : ( imm.u64 == o.imm.u64 && imm.bit_count == o.imm.bit_count ); }
		bool operator<( const operand& o ) const { return is_register() ? reg < o.reg : ( imm.u64 < o.imm.u64 || imm.bit_count < o.imm.bit_count ); }
	};
};