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

// Furthermore, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information                   |
// |-------------------------|------------------------------------------------|
// | arm64/*                 | https://github.com/aquynh/capstone/            |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#pragma once
#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <set>
#include <capstone/capstone.h>
#include <algorithm>
#include "../../io/formatting.hpp"

namespace vtil::arm64
{
	// TODO: abstract, we can share initial fields/logic with amd64
	// 
	struct instruction
	{
		// Data copied from base of [cs_insn].
		//
		uint32_t id = 0;
		uint64_t address = 0;
		std::vector<uint8_t> bytes;
		std::string mnemonic;
		std::string operand_string;

		// Data copied from [cs_insn::detail].
		//
		std::set<uint16_t> regs_read;
		std::set<uint16_t> regs_write;
		std::set<uint8_t> groups;

		// Data copied from [cs_insn::detail::arm64]
		//
		arm64_cc cc = ARM64_CC_INVALID;
		bool update_flags = false;
		bool writeback = false;
		std::vector<cs_arm64_op> operands;

		// Returns human readable disassembly.
		//
		std::string to_string() const
		{
			return format::str( "%p: %s\t%s", address, mnemonic, operand_string );
		}

		// Helper to check if instruction is of type <x86_INS_*, {X86_OP_*...}>.
		//
		bool is( uint32_t idx, const std::vector<arm64_op_type>& operand_types ) const
		{
			if ( id != idx ) return false;
			if ( operands.size() != operand_types.size() ) return false;
			for ( int i = 0; i < operands.size(); i++ )
				if ( operands[ i ].type != operand_types[ i ] )
					return false;
			return true;
		}

		// Helper to check if instruction belongs to the given group.
		//
		bool in_group( uint8_t group_searched ) const
		{
			return std::find( groups.begin(), groups.end(), group_searched ) != groups.end();
		}
	};

	csh get_cs_handle();
	std::vector<instruction> disasm( const void* bytes, uint64_t address, size_t size = 0, size_t count = 1 );
}
