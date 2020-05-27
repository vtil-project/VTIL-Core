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
#include <set>
#include "../arch/register_desc.hpp"

// List of calling conventions supported.
//
#define VTIL_CCONV_AMD64_WINDOWS 0
#define VTIL_CCONV_AMD64_UNIX    1

// [Configuration]
// Determine which calling convention we should default to.
//
#ifndef VTIL_DEFAULT_CALL_CONV
	#define VTIL_DEFAULT_CALL_CONV VTIL_CCONV_AMD64_WINDOWS
#endif

namespace vtil
{
	// Declares a calling convention to be used during the elimination of dead stores 
	// and determining dependencies of an exiting call.
	//
	struct call_convention
	{
		// List of registers that may change as a result of the routine execution but
		// will be considered trashed.
		//
		std::set<register_desc> volatile_registers = {};

		// List of regsiters that this routine should not touch at all.
		//
		std::set<register_desc> forbidden_registers = {};

		// List of registers that are used to store the return value of the routine and
		// thus will change during routine execution but must be considered "used" by return.
		//
		std::set<register_desc> retval_registers = {};

		// Register that is generally used to store the stack frame if relevant.
		//
		register_desc frame_register = {};
		
		// Purges any writes to stack that will be end up below the final stack pointer.
		//
		bool purge_stack = false;
	};

#if VTIL_DEFAULT_CALL_CONV == VTIL_CCONV_AMD64_WINDOWS || VTIL_DEFAULT_CALL_CONV == VTIL_CCONV_AMD64_UNIX
	// Define a convention preserving all changes.
	//
	static const call_convention preserve_all_convention = {
		/*.volatile_registers =*/ {},
		/*.forbidden_registers =*/ {},
		/*.retval_registers =*/ { 
			// Callee reads whole context.
			//
			{ register_physical, X86_REG_RAX, 64 }, { register_physical, X86_REG_RBX, 64 },
			{ register_physical, X86_REG_RCX, 64 }, { register_physical, X86_REG_RDX, 64 },
			{ register_physical, X86_REG_RSI, 64 }, { register_physical, X86_REG_RDI, 64 },
			{ register_physical, X86_REG_RBP, 64 }, { register_physical, X86_REG_RSP, 64 },
			{ register_physical, X86_REG_R8,  64 }, { register_physical, X86_REG_R9,  64 },
			{ register_physical, X86_REG_R10, 64 }, { register_physical, X86_REG_R11, 64 },
			{ register_physical, X86_REG_R12, 64 }, { register_physical, X86_REG_R13, 64 },
			{ register_physical, X86_REG_R14, 64 }, { register_physical, X86_REG_R15, 64 },
			REG_FLAGS,
		},
		{ register_physical, X86_REG_RBP, 64 },
		/*.purge_stack =*/ true,
	};
#else
	#error "Unknown call convention."
#endif

	// Define the default call convention.
	//
#if VTIL_DEFAULT_CALL_CONV == VTIL_CCONV_AMD64_WINDOWS
	static const call_convention default_call_convention = {
		/*.volatile_registers =*/ {
			// Parameters of an ABI-abiding routine.
			//
			{ register_physical, X86_REG_RCX, 64 }, { register_physical, X86_REG_RDX, 64 }, 
			{ register_physical, X86_REG_R8,  64 }, { register_physical, X86_REG_R9,  64 }, 
			{ register_physical, X86_REG_R10, 64 }, { register_physical, X86_REG_R11, 64 },

			// Every bit except the direction flag.
			//
			{ register_physical | register_flags, 0, 10, 0  },
			{ register_physical | register_flags, 0, 53, 11 }
		},
		/*.forbidden_registers =*/ {},
		/*.retval_registers =*/ {
			// Single integral return.
			//
			{ register_physical, X86_REG_RAX, 64 },
		},
		/*.frame_register =*/ { register_physical, X86_REG_RBP, 64 },
		/*.purge_stack =*/ true,
	};
#elif VTIL_DEFAULT_CALL_CONV == VTIL_CCONV_AMD64_UNIX
	static const call_convention default_call_convention = {
		/*.volatile_registers =*/ {
			// Parameters of an ABI-abiding routine.
			//
			{ register_physical, X86_REG_RDI, 64 }, { register_physical, X86_REG_RSI, 64 }, 
			{ register_physical, X86_REG_R8,  64 }, { register_physical, X86_REG_R9,  64 },

			// Every bit except the direction flag.
			//
			{ register_physical | register_flags, 0, 10, 0  },
			{ register_physical | register_flags, 0, 53, 11 }
		},
		/*.forbidden_registers =*/ {},
		/*.retval_registers =*/ { 
			// Double integral return @ [LOW:HIGH].
			//
			{ register_physical, X86_REG_RAX, 64 },
			{ register_physical, X86_REG_RDX, 64 }
		},
		/*.frame_register =*/ { register_physical, X86_REG_RBP, 64 },
		/*.purge_stack =*/ true,
	};
#else
	#error "Unknown call convention."
#endif
};