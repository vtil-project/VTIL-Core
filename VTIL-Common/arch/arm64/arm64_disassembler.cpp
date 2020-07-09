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
#include "arm64_disassembler.hpp"
#include <stdexcept>

namespace vtil::arm64
{
	csh get_cs_handle()
	{
		// Capstone engine is not created until the first call.
		//
		static csh handle = [ ] ()
		{
			csh handle;
			if ( cs_open( CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle ) != CS_ERR_OK 
				 || cs_option( handle, CS_OPT_DETAIL, CS_OPT_ON ) != CS_ERR_OK )
				throw std::runtime_error( "Failed to create the Capstone engine!" );
			return handle;
		}( );
		return handle;
	}

	std::vector<instruction> disasm(const void* bytes, uint64_t address, size_t size, size_t count)
	{
		// Disasemble the instruction.
		//
		cs_insn* ins;
		count = cs_disasm
		(
			get_cs_handle(),
			( uint8_t* ) bytes,
			size ? size : -1,
			address,
			size ? 0 : count,
			&ins
		);

		// Convert each output into vtil::arm64 format and push it to a vector.
		//
		std::vector<instruction> vec;
		for ( int i = 0; i < count; i++ )
		{
			instruction out;
			cs_insn& in = ins[ i ];

			// Copy cs_insn base.
			//
			out.id = in.id;
			out.address = in.address;
			out.mnemonic = in.mnemonic;
			out.operand_string = in.op_str;
			out.bytes = { in.bytes, in.bytes + in.size };

			// Copy cs_insn::detail.
			//
			out.regs_read = { in.detail->regs_read, in.detail->regs_read + in.detail->regs_read_count };
			out.regs_write = { in.detail->regs_write, in.detail->regs_write + in.detail->regs_write_count };
			out.groups = { in.detail->groups, in.detail->groups + in.detail->groups_count };

			// Copy cs_insn::detail::arm64.
			//
			out.cc = in.detail->arm64.cc;
			out.update_flags = in.detail->arm64.update_flags;
			out.writeback = in.detail->arm64.writeback;
			out.operands = { in.detail->arm64.operands, in.detail->arm64.operands + in.detail->arm64.op_count };

			// Push it to up the vector.
			//
			vec.push_back( std::move( out ) );
		}

		// Free the output from Capstone and return the vector.
		//
		cs_free( ins, count );
		return vec;
	}
}
