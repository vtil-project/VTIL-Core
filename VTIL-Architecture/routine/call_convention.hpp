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

		// List of regsiters that this routine wlil read from as a way of taking arguments.
		// - Any additional arguments will be passed at [$sp + shadow_space + n*8]
		//
		std::set<register_desc> param_registers = {};

		// List of registers that are used to store the return value of the routine and
		// thus will change during routine execution but must be considered "used" by return.
		//
		std::set<register_desc> retval_registers = {};

		// Register that is generally used to store the stack frame if relevant.
		//
		register_desc frame_register = {};
		
		// Size of the shadow space.
		//
		size_t shadow_space = 0;
		
		// Purges any writes to stack that will be end up below the final stack pointer.
		//
		bool purge_stack = false;
	};
	
	namespace amd64
	{
		// Define a convention preserving all changes.
		//
		static const call_convention preserve_all_convention = {
			/*.volatile_registers =*/ {
				{ register_physical, X86_REG_RAX, 64 }, { register_physical, X86_REG_RBX, 64 },
				{ register_physical, X86_REG_RCX, 64 }, { register_physical, X86_REG_RDX, 64 },
				{ register_physical, X86_REG_RSI, 64 }, { register_physical, X86_REG_RDI, 64 },
				{ register_physical, X86_REG_RBP, 64 }, { register_physical, X86_REG_R8,  64 },
				{ register_physical, X86_REG_R9,  64 }, { register_physical, X86_REG_R10, 64 },
				{ register_physical, X86_REG_R11, 64 }, { register_physical, X86_REG_R12, 64 },
				{ register_physical, X86_REG_R13, 64 }, { register_physical, X86_REG_R14, 64 },
				{ register_physical, X86_REG_R15, 64 },
				REG_FLAGS,
			},

			/*.param_registers =*/ {
				{ register_physical, X86_REG_RAX, 64 }, { register_physical, X86_REG_RBX, 64 },
				{ register_physical, X86_REG_RCX, 64 }, { register_physical, X86_REG_RDX, 64 },
				{ register_physical, X86_REG_RSI, 64 }, { register_physical, X86_REG_RDI, 64 },
				{ register_physical, X86_REG_RBP, 64 }, { register_physical, X86_REG_R8,  64 },
				{ register_physical, X86_REG_R9,  64 }, { register_physical, X86_REG_R10, 64 },
				{ register_physical, X86_REG_R11, 64 }, { register_physical, X86_REG_R12, 64 },
				{ register_physical, X86_REG_R13, 64 }, { register_physical, X86_REG_R14, 64 },
				{ register_physical, X86_REG_R15, 64 },
				REG_FLAGS,
			},

			/*.retval_registers =*/ {
				{ register_physical, X86_REG_RAX, 64 }, { register_physical, X86_REG_RBX, 64 },
				{ register_physical, X86_REG_RCX, 64 }, { register_physical, X86_REG_RDX, 64 },
				{ register_physical, X86_REG_RSI, 64 }, { register_physical, X86_REG_RDI, 64 },
				{ register_physical, X86_REG_RBP, 64 }, { register_physical, X86_REG_R8,  64 },
				{ register_physical, X86_REG_R9,  64 }, { register_physical, X86_REG_R10, 64 },
				{ register_physical, X86_REG_R11, 64 }, { register_physical, X86_REG_R12, 64 },
				{ register_physical, X86_REG_R13, 64 }, { register_physical, X86_REG_R14, 64 },
				{ register_physical, X86_REG_R15, 64 },
				REG_FLAGS,
			},

			/*.frame_register =*/
			{ register_physical, X86_REG_RBP, 64 },

			/*.shadow_space =*/
			0x0,

			/*.purge_stack =*/
			true,
		};

		static const call_convention default_call_convention = {
			/*.volatile_registers =*/ {
				{ register_physical, X86_REG_RCX, 64 }, { register_physical, X86_REG_RDX, 64 },
				{ register_physical, X86_REG_R8,  64 }, { register_physical, X86_REG_R9,  64 },
				{ register_physical, X86_REG_R10, 64 }, { register_physical, X86_REG_R11, 64 },
				REG_FLAGS,
			},

			/*.param_registers =*/ {
				{ register_physical, X86_REG_RCX, 64 }, { register_physical, X86_REG_RDX, 64 },
				{ register_physical, X86_REG_R8,  64 }, { register_physical, X86_REG_R9,  64 },
			},

			/*.retval_registers =*/ {
				{ register_physical, X86_REG_RAX, 64 },
			},

			/*.frame_register =*/
			{ register_physical, X86_REG_RBP, 64 },

			/*.shadow_space =*/
			0x20,

			/*.purge_stack =*/
			true,
		};
	}

	namespace arm64
	{
		// Define a convention preserving all changes.
		//
		static const call_convention preserve_all_convention = {
			/*.volatile_registers =*/ {
				{ register_physical, ARM64_REG_X0,  64 }, { register_physical, ARM64_REG_X1,  64 },
				{ register_physical, ARM64_REG_X2,  64 }, { register_physical, ARM64_REG_X3,  64 },
				{ register_physical, ARM64_REG_X4,  64 }, { register_physical, ARM64_REG_X5,  64 },
				{ register_physical, ARM64_REG_X6,  64 }, { register_physical, ARM64_REG_X7,  64 },
				{ register_physical, ARM64_REG_X8,  64 }, { register_physical, ARM64_REG_X9,  64 },
				{ register_physical, ARM64_REG_X10, 64 }, { register_physical, ARM64_REG_X11, 64 },
				{ register_physical, ARM64_REG_X12, 64 }, { register_physical, ARM64_REG_X13, 64 },
				{ register_physical, ARM64_REG_X14, 64 }, { register_physical, ARM64_REG_X15, 64 },
				{ register_physical, ARM64_REG_X16, 64 }, { register_physical, ARM64_REG_X17, 64 },
				{ register_physical, ARM64_REG_X18, 64 }, { register_physical, ARM64_REG_X19, 64 },
				{ register_physical, ARM64_REG_X20, 64 }, { register_physical, ARM64_REG_X21, 64 },
				{ register_physical, ARM64_REG_X22, 64 }, { register_physical, ARM64_REG_X23, 64 },
				{ register_physical, ARM64_REG_X24, 64 }, { register_physical, ARM64_REG_X25, 64 },
				{ register_physical, ARM64_REG_X26, 64 }, { register_physical, ARM64_REG_X27, 64 },
				{ register_physical, ARM64_REG_X28, 64 }, { register_physical, ARM64_REG_X29, 64 },
				{ register_physical, ARM64_REG_X30, 64 }, { register_physical, ARM64_REG_SP,  64 },
				REG_FLAGS,

				/* SIMD */
				/*{ register_physical, ARM64_REG_V0,  128 }, { register_physical, ARM64_REG_V1,  128 },
				{ register_physical, ARM64_REG_V2,  128 }, { register_physical, ARM64_REG_V3,  128 },
				{ register_physical, ARM64_REG_V4,  128 }, { register_physical, ARM64_REG_V5,  128 },
				{ register_physical, ARM64_REG_V6,  128 }, { register_physical, ARM64_REG_V7,  128 },
				{ register_physical, ARM64_REG_V8,  128 }, { register_physical, ARM64_REG_V9,  128 },
				{ register_physical, ARM64_REG_V10, 128 }, { register_physical, ARM64_REG_V11, 128 },
				{ register_physical, ARM64_REG_V12, 128 }, { register_physical, ARM64_REG_V13, 128 },
				{ register_physical, ARM64_REG_V14, 128 }, { register_physical, ARM64_REG_V15, 128 },
				{ register_physical, ARM64_REG_V16, 128 }, { register_physical, ARM64_REG_V17, 128 },
				{ register_physical, ARM64_REG_V18, 128 }, { register_physical, ARM64_REG_V19, 128 },
				{ register_physical, ARM64_REG_V20, 128 }, { register_physical, ARM64_REG_V21, 128 },
				{ register_physical, ARM64_REG_V22, 128 }, { register_physical, ARM64_REG_V23, 128 },
				{ register_physical, ARM64_REG_V24, 128 }, { register_physical, ARM64_REG_V25, 128 },
				{ register_physical, ARM64_REG_V26, 128 }, { register_physical, ARM64_REG_V27, 128 },
				{ register_physical, ARM64_REG_V28, 128 }, { register_physical, ARM64_REG_V28, 128 },
				{ register_physical, ARM64_REG_V30, 128 }, { register_physical, ARM64_REG_V31, 128 }*/
			},

			/*.param_registers =*/ {
				{ register_physical, ARM64_REG_X0,  64 }, { register_physical, ARM64_REG_X1,  64 },
				{ register_physical, ARM64_REG_X2,  64 }, { register_physical, ARM64_REG_X3,  64 },
				{ register_physical, ARM64_REG_X4,  64 }, { register_physical, ARM64_REG_X5,  64 },
				{ register_physical, ARM64_REG_X6,  64 }, { register_physical, ARM64_REG_X7,  64 },
				{ register_physical, ARM64_REG_X8,  64 }, { register_physical, ARM64_REG_X9,  64 },
				{ register_physical, ARM64_REG_X10, 64 }, { register_physical, ARM64_REG_X11, 64 },
				{ register_physical, ARM64_REG_X12, 64 }, { register_physical, ARM64_REG_X13, 64 },
				{ register_physical, ARM64_REG_X14, 64 }, { register_physical, ARM64_REG_X15, 64 },
				{ register_physical, ARM64_REG_X16, 64 }, { register_physical, ARM64_REG_X17, 64 },
				{ register_physical, ARM64_REG_X18, 64 }, { register_physical, ARM64_REG_X19, 64 },
				{ register_physical, ARM64_REG_X20, 64 }, { register_physical, ARM64_REG_X21, 64 },
				{ register_physical, ARM64_REG_X22, 64 }, { register_physical, ARM64_REG_X23, 64 },
				{ register_physical, ARM64_REG_X24, 64 }, { register_physical, ARM64_REG_X25, 64 },
				{ register_physical, ARM64_REG_X26, 64 }, { register_physical, ARM64_REG_X27, 64 },
				{ register_physical, ARM64_REG_X28, 64 }, { register_physical, ARM64_REG_X29, 64 },
				{ register_physical, ARM64_REG_X30, 64 }, { register_physical, ARM64_REG_SP,  64 },
				REG_FLAGS,

				/* SIMD */
				/*{ register_physical, ARM64_REG_V0,  128 }, { register_physical, ARM64_REG_V1,  128 },
				{ register_physical, ARM64_REG_V2,  128 }, { register_physical, ARM64_REG_V3,  128 },
				{ register_physical, ARM64_REG_V4,  128 }, { register_physical, ARM64_REG_V5,  128 },
				{ register_physical, ARM64_REG_V6,  128 }, { register_physical, ARM64_REG_V7,  128 },
				{ register_physical, ARM64_REG_V8,  128 }, { register_physical, ARM64_REG_V9,  128 },
				{ register_physical, ARM64_REG_V10, 128 }, { register_physical, ARM64_REG_V11, 128 },
				{ register_physical, ARM64_REG_V12, 128 }, { register_physical, ARM64_REG_V13, 128 },
				{ register_physical, ARM64_REG_V14, 128 }, { register_physical, ARM64_REG_V15, 128 },
				{ register_physical, ARM64_REG_V16, 128 }, { register_physical, ARM64_REG_V17, 128 },
				{ register_physical, ARM64_REG_V18, 128 }, { register_physical, ARM64_REG_V19, 128 },
				{ register_physical, ARM64_REG_V20, 128 }, { register_physical, ARM64_REG_V21, 128 },
				{ register_physical, ARM64_REG_V22, 128 }, { register_physical, ARM64_REG_V23, 128 },
				{ register_physical, ARM64_REG_V24, 128 }, { register_physical, ARM64_REG_V25, 128 },
				{ register_physical, ARM64_REG_V26, 128 }, { register_physical, ARM64_REG_V27, 128 },
				{ register_physical, ARM64_REG_V28, 128 }, { register_physical, ARM64_REG_V28, 128 },
				{ register_physical, ARM64_REG_V30, 128 }, { register_physical, ARM64_REG_V31, 128 }*/
			},

			/*.retval_registers =*/ {
				{ register_physical, ARM64_REG_X0,  64 }, { register_physical, ARM64_REG_X1,  64 },
				{ register_physical, ARM64_REG_X2,  64 }, { register_physical, ARM64_REG_X3,  64 },
				{ register_physical, ARM64_REG_X4,  64 }, { register_physical, ARM64_REG_X5,  64 },
				{ register_physical, ARM64_REG_X6,  64 }, { register_physical, ARM64_REG_X7,  64 },
				{ register_physical, ARM64_REG_X8,  64 }, { register_physical, ARM64_REG_X9,  64 },
				{ register_physical, ARM64_REG_X10, 64 }, { register_physical, ARM64_REG_X11, 64 },
				{ register_physical, ARM64_REG_X12, 64 }, { register_physical, ARM64_REG_X13, 64 },
				{ register_physical, ARM64_REG_X14, 64 }, { register_physical, ARM64_REG_X15, 64 },
				{ register_physical, ARM64_REG_X16, 64 }, { register_physical, ARM64_REG_X17, 64 },
				{ register_physical, ARM64_REG_X18, 64 }, { register_physical, ARM64_REG_X19, 64 },
				{ register_physical, ARM64_REG_X20, 64 }, { register_physical, ARM64_REG_X21, 64 },
				{ register_physical, ARM64_REG_X22, 64 }, { register_physical, ARM64_REG_X23, 64 },
				{ register_physical, ARM64_REG_X24, 64 }, { register_physical, ARM64_REG_X25, 64 },
				{ register_physical, ARM64_REG_X26, 64 }, { register_physical, ARM64_REG_X27, 64 },
				{ register_physical, ARM64_REG_X28, 64 }, { register_physical, ARM64_REG_X29, 64 },
				{ register_physical, ARM64_REG_X30, 64 }, { register_physical, ARM64_REG_SP,  64 },
				REG_FLAGS,

				/* SIMD */
				/*{ register_physical, ARM64_REG_V0,  128 }, { register_physical, ARM64_REG_V1,  128 },
				{ register_physical, ARM64_REG_V2,  128 }, { register_physical, ARM64_REG_V3,  128 },
				{ register_physical, ARM64_REG_V4,  128 }, { register_physical, ARM64_REG_V5,  128 },
				{ register_physical, ARM64_REG_V6,  128 }, { register_physical, ARM64_REG_V7,  128 },
				{ register_physical, ARM64_REG_V8,  128 }, { register_physical, ARM64_REG_V9,  128 },
				{ register_physical, ARM64_REG_V10, 128 }, { register_physical, ARM64_REG_V11, 128 },
				{ register_physical, ARM64_REG_V12, 128 }, { register_physical, ARM64_REG_V13, 128 },
				{ register_physical, ARM64_REG_V14, 128 }, { register_physical, ARM64_REG_V15, 128 },
				{ register_physical, ARM64_REG_V16, 128 }, { register_physical, ARM64_REG_V17, 128 },
				{ register_physical, ARM64_REG_V18, 128 }, { register_physical, ARM64_REG_V19, 128 },
				{ register_physical, ARM64_REG_V20, 128 }, { register_physical, ARM64_REG_V21, 128 },
				{ register_physical, ARM64_REG_V22, 128 }, { register_physical, ARM64_REG_V23, 128 },
				{ register_physical, ARM64_REG_V24, 128 }, { register_physical, ARM64_REG_V25, 128 },
				{ register_physical, ARM64_REG_V26, 128 }, { register_physical, ARM64_REG_V27, 128 },
				{ register_physical, ARM64_REG_V28, 128 }, { register_physical, ARM64_REG_V28, 128 },
				{ register_physical, ARM64_REG_V30, 128 }, { register_physical, ARM64_REG_V31, 128 }*/
			},

			/*.frame_register =*/
			{ register_physical, ARM64_REG_X29, 64 },

			/*.shadow_space =*/
			0x0,

			/*.purge_stack =*/
			true,
		};

		static const call_convention default_call_convention = {
			/*.volatile_registers =*/ {
				{ register_physical, ARM64_REG_X0,  64 }, { register_physical, ARM64_REG_X1,  64 },
				{ register_physical, ARM64_REG_X2,  64 }, { register_physical, ARM64_REG_X3,  64 },
				{ register_physical, ARM64_REG_X4,  64 }, { register_physical, ARM64_REG_X5,  64 },
				{ register_physical, ARM64_REG_X6,  64 }, { register_physical, ARM64_REG_X7,  64 },
				{ register_physical, ARM64_REG_X8,  64 }, { register_physical, ARM64_REG_X9,  64 },
				{ register_physical, ARM64_REG_X10, 64 }, { register_physical, ARM64_REG_X11, 64 },
				{ register_physical, ARM64_REG_X12, 64 }, { register_physical, ARM64_REG_X13, 64 },
				{ register_physical, ARM64_REG_X14, 64 }, { register_physical, ARM64_REG_X15, 64 },
				{ register_physical, ARM64_REG_X16, 64 }, { register_physical, ARM64_REG_X17, 64 },
				{ register_physical, ARM64_REG_X18, 64 }, REG_FLAGS,

				/* SIMD */
				/*{ register_physical, ARM64_REG_V0,  128 }, { register_physical, ARM64_REG_V1,  128 },
				{ register_physical, ARM64_REG_V2,  128 }, { register_physical, ARM64_REG_V3,  128 },
				{ register_physical, ARM64_REG_V4,  128 }, { register_physical, ARM64_REG_V5,  128 },
				{ register_physical, ARM64_REG_V6,  128 }, { register_physical, ARM64_REG_V7,  128 },
				{ register_physical, ARM64_REG_V16, 128 }, { register_physical, ARM64_REG_V17, 128 },
				{ register_physical, ARM64_REG_V18, 128 }, { register_physical, ARM64_REG_V19, 128 },
				{ register_physical, ARM64_REG_V20, 128 }, { register_physical, ARM64_REG_V21, 128 },
				{ register_physical, ARM64_REG_V22, 128 }, { register_physical, ARM64_REG_V23, 128 },
				{ register_physical, ARM64_REG_V24, 128 }, { register_physical, ARM64_REG_V25, 128 },
				{ register_physical, ARM64_REG_V26, 128 }, { register_physical, ARM64_REG_V27, 128 },
				{ register_physical, ARM64_REG_V28, 128 }, { register_physical, ARM64_REG_V28, 128 },
				{ register_physical, ARM64_REG_V30, 128 }, { register_physical, ARM64_REG_V31, 128 },*/
			},

			/*.param_registers =*/ {
				{ register_physical, ARM64_REG_X0,  64 }, { register_physical, ARM64_REG_X1,  64 },
				{ register_physical, ARM64_REG_X2,  64 }, { register_physical, ARM64_REG_X3,  64 },
				{ register_physical, ARM64_REG_X4,  64 }, { register_physical, ARM64_REG_X5,  64 },
				{ register_physical, ARM64_REG_X6,  64 }, { register_physical, ARM64_REG_X7,  64 },

				/* SIMD */
				/*{ register_physical, ARM64_REG_V0,  128 }, { register_physical, ARM64_REG_V1,  128 },
				{ register_physical, ARM64_REG_V2,  128 }, { register_physical, ARM64_REG_V3,  128 },
				{ register_physical, ARM64_REG_V4,  128 }, { register_physical, ARM64_REG_V5,  128 },
				{ register_physical, ARM64_REG_V6,  128 }, { register_physical, ARM64_REG_V7,  128 },*/
			},

			/*.retval_registers =*/ {
				{ register_physical, ARM64_REG_X0, 64 },
				/*{ register_physical, ARM64_REG_V0, 128 },*/
			},

			/*.frame_register =*/
			{ register_physical, ARM64_REG_X29, 64 },

			/*.shadow_space =*/
			0x0,

			/*.purge_stack =*/
			true,
		};

		static const call_convention vector_call_convention = {
			/*.volatile_registers =*/ {
				{ register_physical, ARM64_REG_X0,  64 }, { register_physical, ARM64_REG_X1,  64 },
				{ register_physical, ARM64_REG_X2,  64 }, { register_physical, ARM64_REG_X3,  64 },
				{ register_physical, ARM64_REG_X4,  64 }, { register_physical, ARM64_REG_X5,  64 },
				{ register_physical, ARM64_REG_X6,  64 }, { register_physical, ARM64_REG_X7,  64 },
				{ register_physical, ARM64_REG_X8,  64 }, { register_physical, ARM64_REG_X9,  64 },
				{ register_physical, ARM64_REG_X10, 64 }, { register_physical, ARM64_REG_X11, 64 },
				{ register_physical, ARM64_REG_X12, 64 }, { register_physical, ARM64_REG_X13, 64 },
				{ register_physical, ARM64_REG_X14, 64 }, { register_physical, ARM64_REG_X15, 64 },
				{ register_physical, ARM64_REG_X16, 64 }, { register_physical, ARM64_REG_X17, 64 },
				{ register_physical, ARM64_REG_X18, 64 }, REG_FLAGS,

				/* SIMD */
				/*{ register_physical, ARM64_REG_V0,  128 }, { register_physical, ARM64_REG_V1,  128 },
				{ register_physical, ARM64_REG_V2,  128 }, { register_physical, ARM64_REG_V3,  128 },
				{ register_physical, ARM64_REG_V4,  128 }, { register_physical, ARM64_REG_V5,  128 },
				{ register_physical, ARM64_REG_V6,  128 }, { register_physical, ARM64_REG_V7,  128 },
				{ register_physical, ARM64_REG_V16, 128 }, { register_physical, ARM64_REG_V17, 128 },
				{ register_physical, ARM64_REG_V18, 128 }, { register_physical, ARM64_REG_V19, 128 },
				{ register_physical, ARM64_REG_V20, 128 }, { register_physical, ARM64_REG_V21, 128 },
				{ register_physical, ARM64_REG_V22, 128 }, { register_physical, ARM64_REG_V23, 128 },
				{ register_physical, ARM64_REG_V24, 128 }, { register_physical, ARM64_REG_V25, 128 },
				{ register_physical, ARM64_REG_V26, 128 }, { register_physical, ARM64_REG_V27, 128 },
				{ register_physical, ARM64_REG_V28, 128 }, { register_physical, ARM64_REG_V28, 128 },
				{ register_physical, ARM64_REG_V30, 128 }, { register_physical, ARM64_REG_V31, 128 },*/
			},

			/*.param_registers =*/ {
				{ register_physical, ARM64_REG_X0,  64 }, { register_physical, ARM64_REG_X1,  64 },
				{ register_physical, ARM64_REG_X2,  64 }, { register_physical, ARM64_REG_X3,  64 },
				{ register_physical, ARM64_REG_X4,  64 }, { register_physical, ARM64_REG_X5,  64 },
				{ register_physical, ARM64_REG_X6,  64 }, { register_physical, ARM64_REG_X7,  64 },

				/* SIMD */
				/*{ register_physical, ARM64_REG_V0,  128 }, { register_physical, ARM64_REG_V1,  128 },
				{ register_physical, ARM64_REG_V2,  128 }, { register_physical, ARM64_REG_V3,  128 },
				{ register_physical, ARM64_REG_V4,  128 }, { register_physical, ARM64_REG_V5,  128 },
				{ register_physical, ARM64_REG_V6,  128 }, { register_physical, ARM64_REG_V7,  128 },*/
			},

			/*.retval_registers =*/ {
				{ register_physical, ARM64_REG_X0, 64 },
				/*{ register_physical, ARM64_REG_V0, 128 },
				{ register_physical, ARM64_REG_V1, 128 },
				{ register_physical, ARM64_REG_V2, 128 },
				{ register_physical, ARM64_REG_V3, 128 },*/
			},

			/*.frame_register =*/
			{ register_physical, ARM64_REG_X29, 64 },

			/*.shadow_space =*/
			0x0,

			/*.purge_stack =*/
			true,
		};
	}
};