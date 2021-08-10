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

// Furthermore, the following pieces of software have additional copyright
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information                   |
// |-------------------------|------------------------------------------------|
// | x86/*                   | https://github.com/aquynh/capstone/            |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#pragma once
#include <map>
#include <tuple>
#include <string>
#include "../../io/asserts.hpp"
#include "x86_disassembler.hpp"
#include "../register_mapping.hpp"

namespace vtil::x86
{
    // List of all physical registers and the base registers they map to <0> at offset <1> of size <2>.
	//
	static constexpr register_map<x86_reg, X86_REG_ENDING> registers =
	{
		{
            /* [Instance]           [Base]       [Offset] [Size]  */
            { X86_REG_EAX,		{ X86_REG_EAX,		0,		4	} },
            { X86_REG_AX,		{ X86_REG_EAX,		0,		2	} },
            { X86_REG_AH,		{ X86_REG_EAX,		1,		1	} },
            { X86_REG_AL,		{ X86_REG_EAX,		0,		1	} },

            { X86_REG_EBX,		{ X86_REG_EBX,		0,		4	} },
            { X86_REG_BX,		{ X86_REG_EBX,		0,		2	} },
            { X86_REG_BH,		{ X86_REG_EBX,		1,		1	} },
            { X86_REG_BL,		{ X86_REG_EBX,		0,		1	} },

            { X86_REG_ECX,		{ X86_REG_ECX,		0,		4	} },
            { X86_REG_CX,		{ X86_REG_ECX,		0,		2	} },
            { X86_REG_CH,		{ X86_REG_ECX,		1,		1	} },
            { X86_REG_CL,		{ X86_REG_ECX,		0,		1	} },

            { X86_REG_EDX,		{ X86_REG_EDX,		0,		4	} },
            { X86_REG_DX,		{ X86_REG_EDX,		0,		2	} },
            { X86_REG_DH,		{ X86_REG_EDX,		1,		1	} },
            { X86_REG_DL,		{ X86_REG_EDX,		0,		1	} },

            { X86_REG_EDI,		{ X86_REG_EDI,		0,		4	} },
            { X86_REG_DI,		{ X86_REG_EDI,		0,		2	} },
            { X86_REG_DIL,		{ X86_REG_EDI,		0,		1	} },

            { X86_REG_ESI,		{ X86_REG_ESI,		0,		4	} },
            { X86_REG_SI,		{ X86_REG_ESI,		0,		2	} },
            { X86_REG_SIL,		{ X86_REG_ESI,		0,		1	} },

            { X86_REG_EBP,		{ X86_REG_EBP,		0,		4	} },
            { X86_REG_BP,		{ X86_REG_EBP,		0,		2	} },
            { X86_REG_BPL,		{ X86_REG_EBP,		0,		1	} },

            { X86_REG_ESP,		{ X86_REG_ESP,		0,		4	} },
            { X86_REG_SP,		{ X86_REG_ESP,		0,		2	} },
            { X86_REG_SPL,		{ X86_REG_ESP,		0,		1	} },

            { X86_REG_EFLAGS,	{ X86_REG_EFLAGS,	0,		4	} },
		}
	};

	// Converts the enum into human-readable format.
	//
	static const char* name( uint32_t _reg ) { return cs_reg_name( get_cs_handle(), _reg ); }
};
