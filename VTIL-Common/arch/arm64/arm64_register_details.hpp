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
#include <map>
#include <tuple>
#include <string>
#include <stdexcept>
#include "arm64_disassembler.hpp"
#include "../register_mapping.hpp"

namespace vtil::arm64
{
	// Structure describing how a register maps to another register in aarch64.
	//
	using register_mapping = vtil::register_mapping<arm64_reg>;

	// List of all physical registers and the base registers they map to <0> at offset <1> of size <2>.
	//
	static constexpr std::pair<arm64_reg, register_mapping> register_mappings[] =
	{
		/* [Instance]           [Base]       [Offset] [Size]  */
		/*                   General Purpose                  */
		{ ARM64_REG_X0,		{ ARM64_REG_X0,		0,		8	} },
		{ ARM64_REG_W0,		{ ARM64_REG_X0,		0,		4	} },

		{ ARM64_REG_X1,		{ ARM64_REG_X1,		0,		8	} },
		{ ARM64_REG_W1,		{ ARM64_REG_X1,		0,		4	} },

		{ ARM64_REG_X2,		{ ARM64_REG_X2,		0,		8	} },
		{ ARM64_REG_W2,		{ ARM64_REG_X2,		0,		4	} },

		{ ARM64_REG_X3,		{ ARM64_REG_X3,		0,		8	} },
		{ ARM64_REG_W3,		{ ARM64_REG_X3,		0,		4	} },

		{ ARM64_REG_X4,		{ ARM64_REG_X4,		0,		8	} },
		{ ARM64_REG_W4,		{ ARM64_REG_X4,		0,		4	} },

		{ ARM64_REG_X5,		{ ARM64_REG_X5,		0,		8	} },
		{ ARM64_REG_W5,		{ ARM64_REG_X5,		0,		4	} },

		{ ARM64_REG_X6,		{ ARM64_REG_X6,		0,		8	} },
		{ ARM64_REG_W6,		{ ARM64_REG_X6,		0,		4	} },

		{ ARM64_REG_X7,		{ ARM64_REG_X7,		0,		8	} },
		{ ARM64_REG_W7,		{ ARM64_REG_X7,		0,		4	} },

		{ ARM64_REG_X8,		{ ARM64_REG_X8,		0,		8	} },
		{ ARM64_REG_W8,		{ ARM64_REG_X8,		0,		4	} },

		{ ARM64_REG_X9,		{ ARM64_REG_X9,		0,		8	} },
		{ ARM64_REG_W9,		{ ARM64_REG_X9,		0,		4	} },

		{ ARM64_REG_X10,	{ ARM64_REG_X10,	0,		8	} },
		{ ARM64_REG_W10,	{ ARM64_REG_X10,	0,		4	} },

		{ ARM64_REG_X11,	{ ARM64_REG_X11,	0,		8	} },
		{ ARM64_REG_W11,	{ ARM64_REG_X11,	0,		4	} },

		{ ARM64_REG_X12,	{ ARM64_REG_X12,	0,		8	} },
		{ ARM64_REG_W12,	{ ARM64_REG_X12,	0,		4	} },

		{ ARM64_REG_X13,	{ ARM64_REG_X13,	0,		8	} },
		{ ARM64_REG_W13,	{ ARM64_REG_X13,	0,		4	} },

		{ ARM64_REG_X14,	{ ARM64_REG_X14,	0,		8	} },
		{ ARM64_REG_W14,	{ ARM64_REG_X14,	0,		4	} },

		{ ARM64_REG_X15,	{ ARM64_REG_X15,	0,		8	} },
		{ ARM64_REG_W15,	{ ARM64_REG_X15,	0,		4	} },

		{ ARM64_REG_X16,	{ ARM64_REG_X16,	0,		8	} },
		{ ARM64_REG_IP0,	{ ARM64_REG_X16,	0,		8	} },  // alias x16 = ip0
		{ ARM64_REG_W16,	{ ARM64_REG_X16,	0,		4	} },

		{ ARM64_REG_X17,	{ ARM64_REG_X17,	0,		8	} },
		{ ARM64_REG_IP1,	{ ARM64_REG_X17,	0,		8	} },  // alias x17 = ip1
		{ ARM64_REG_W17,	{ ARM64_REG_X17,	0,		4	} },

		{ ARM64_REG_X18,	{ ARM64_REG_X18,	0,		8	} },
		{ ARM64_REG_W18,	{ ARM64_REG_X18,	0,		4	} },

		{ ARM64_REG_X19,	{ ARM64_REG_X19,	0,		8	} },
		{ ARM64_REG_W19,	{ ARM64_REG_X19,	0,		4	} },

		{ ARM64_REG_X20,	{ ARM64_REG_X20,	0,		8	} },
		{ ARM64_REG_W20,	{ ARM64_REG_X20,	0,		4	} },

		{ ARM64_REG_X21,	{ ARM64_REG_X21,	0,		8	} },
		{ ARM64_REG_W21,	{ ARM64_REG_X21,	0,		4	} },

		{ ARM64_REG_X22,	{ ARM64_REG_X22,	0,		8	} },
		{ ARM64_REG_W22,	{ ARM64_REG_X22,	0,		4	} },

		{ ARM64_REG_X23,	{ ARM64_REG_X23,	0,		8	} },
		{ ARM64_REG_W23,	{ ARM64_REG_X23,	0,		4	} },

		{ ARM64_REG_X24,	{ ARM64_REG_X24,	0,		8	} },
		{ ARM64_REG_W24,	{ ARM64_REG_X24,	0,		4	} },

		{ ARM64_REG_X25,	{ ARM64_REG_X25,	0,		8	} },
		{ ARM64_REG_W25,	{ ARM64_REG_X25,	0,		4	} },

		{ ARM64_REG_X26,	{ ARM64_REG_X26,	0,		8	} },
		{ ARM64_REG_W26,	{ ARM64_REG_X26,	0,		4	} },

		{ ARM64_REG_X27,	{ ARM64_REG_X27,	0,		8	} },
		{ ARM64_REG_W27,	{ ARM64_REG_X27,	0,		4	} },

		{ ARM64_REG_X28,	{ ARM64_REG_X28,	0,		8	} },
		{ ARM64_REG_W28,	{ ARM64_REG_X28,	0,		4	} },

		/*                      Special                       */
		{ ARM64_REG_X29,	{ ARM64_REG_X29,	0,		8	} },
		{ ARM64_REG_FP,		{ ARM64_REG_X29,	0,		8	} },  // alias x29 = fp
		{ ARM64_REG_W29,	{ ARM64_REG_X29,	0,		4	} },

		{ ARM64_REG_X30,	{ ARM64_REG_X30,	0,		8	} },
		{ ARM64_REG_LR,		{ ARM64_REG_X30,	0,		8	} },  // alias x30 = lr
		{ ARM64_REG_W30,	{ ARM64_REG_X30,	0,		4	} },

		{ ARM64_REG_XZR,	{ ARM64_REG_XZR,	0,		8	} },
		{ ARM64_REG_WZR,	{ ARM64_REG_XZR,	0,		4	} },

		{ ARM64_REG_SP,		{ ARM64_REG_SP,		0,		8	} },
		{ ARM64_REG_WSP,	{ ARM64_REG_SP,		0,		4	} },

		{ ARM64_REG_NZCV,	{ ARM64_REG_NZCV,	0,		8	} },

		/*                      SIMD/FP                       */
		{ ARM64_REG_V0,		{ ARM64_REG_V0,		0,		16	} },
		{ ARM64_REG_Q0,		{ ARM64_REG_V0,		0,		16	} },  // alias v0 = q0
		{ ARM64_REG_D0,		{ ARM64_REG_V0,		0,		8	} },
		{ ARM64_REG_S0,		{ ARM64_REG_V0,		0,		4	} },
		{ ARM64_REG_H0,		{ ARM64_REG_V0,		0,		2	} },
		{ ARM64_REG_B0,		{ ARM64_REG_V0,		0,		1	} },

		{ ARM64_REG_V1,		{ ARM64_REG_V1,		0,		16	} },
		{ ARM64_REG_Q1,		{ ARM64_REG_V1,		0,		16	} },  // alias v1 = q1
		{ ARM64_REG_D1,		{ ARM64_REG_V1,		0,		8	} },
		{ ARM64_REG_S1,		{ ARM64_REG_V1,		0,		4	} },
		{ ARM64_REG_H1,		{ ARM64_REG_V1,		0,		2	} },
		{ ARM64_REG_B1,		{ ARM64_REG_V1,		0,		1	} },

		{ ARM64_REG_V2,		{ ARM64_REG_V2,		0,		16	} },
		{ ARM64_REG_Q2,		{ ARM64_REG_V2,		0,		16	} },  // alias v2 = q2
		{ ARM64_REG_D2,		{ ARM64_REG_V2,		0,		8	} },
		{ ARM64_REG_S2,		{ ARM64_REG_V2,		0,		4	} },
		{ ARM64_REG_H2,		{ ARM64_REG_V2,		0,		2	} },
		{ ARM64_REG_B2,		{ ARM64_REG_V2,		0,		1	} },

		{ ARM64_REG_V3,		{ ARM64_REG_V3,		0,		16	} },
		{ ARM64_REG_Q3,		{ ARM64_REG_V3,		0,		16	} },  // alias v3 = q3
		{ ARM64_REG_D3,		{ ARM64_REG_V3,		0,		8	} },
		{ ARM64_REG_S3,		{ ARM64_REG_V3,		0,		4	} },
		{ ARM64_REG_H3,		{ ARM64_REG_V3,		0,		2	} },
		{ ARM64_REG_B3,		{ ARM64_REG_V3,		0,		1	} },

		{ ARM64_REG_V4,		{ ARM64_REG_V4,		0,		16	} },
		{ ARM64_REG_Q4,		{ ARM64_REG_V4,		0,		16	} },  // alias v4 = q4
		{ ARM64_REG_D4,		{ ARM64_REG_V4,		0,		8	} },
		{ ARM64_REG_S4,		{ ARM64_REG_V4,		0,		4	} },
		{ ARM64_REG_H4,		{ ARM64_REG_V4,		0,		2	} },
		{ ARM64_REG_B4,		{ ARM64_REG_V4,		0,		1	} },

		{ ARM64_REG_V5,		{ ARM64_REG_V5,		0,		16	} },
		{ ARM64_REG_Q5,		{ ARM64_REG_V5,		0,		16	} },  // alias v5 = q5
		{ ARM64_REG_D5,		{ ARM64_REG_V5,		0,		8	} },
		{ ARM64_REG_S5,		{ ARM64_REG_V5,		0,		4	} },
		{ ARM64_REG_H5,		{ ARM64_REG_V5,		0,		2	} },
		{ ARM64_REG_B5,		{ ARM64_REG_V5,		0,		1	} },

		{ ARM64_REG_V6,		{ ARM64_REG_V6,		0,		16	} },
		{ ARM64_REG_Q6,		{ ARM64_REG_V6,		0,		16	} },  // alias v6 = q6
		{ ARM64_REG_D6,		{ ARM64_REG_V6,		0,		8	} },
		{ ARM64_REG_S6,		{ ARM64_REG_V6,		0,		4	} },
		{ ARM64_REG_H6,		{ ARM64_REG_V6,		0,		2	} },
		{ ARM64_REG_B6,		{ ARM64_REG_V6,		0,		1	} },

		{ ARM64_REG_V7,		{ ARM64_REG_V7,		0,		16	} },
		{ ARM64_REG_Q7,		{ ARM64_REG_V7,		0,		16	} },  // alias v7 = q7
		{ ARM64_REG_D7,		{ ARM64_REG_V7,		0,		8	} },
		{ ARM64_REG_S7,		{ ARM64_REG_V7,		0,		4	} },
		{ ARM64_REG_H7,		{ ARM64_REG_V7,		0,		2	} },
		{ ARM64_REG_B7,		{ ARM64_REG_V7,		0,		1	} },

		{ ARM64_REG_V8,		{ ARM64_REG_V8,		0,		16	} },
		{ ARM64_REG_Q8,		{ ARM64_REG_V8,		0,		16	} },  // alias v8 = q8
		{ ARM64_REG_D8,		{ ARM64_REG_V8,		0,		8	} },
		{ ARM64_REG_S8,		{ ARM64_REG_V8,		0,		4	} },
		{ ARM64_REG_H8,		{ ARM64_REG_V8,		0,		2	} },
		{ ARM64_REG_B8,		{ ARM64_REG_V8,		0,		1	} },

		{ ARM64_REG_V9,		{ ARM64_REG_V9,		0,		16	} },
		{ ARM64_REG_Q9,		{ ARM64_REG_V9,		0,		16	} },  // alias v9 = q9
		{ ARM64_REG_D9,		{ ARM64_REG_V9,		0,		8	} },
		{ ARM64_REG_S9,		{ ARM64_REG_V9,		0,		4	} },
		{ ARM64_REG_H9,		{ ARM64_REG_V9,		0,		2	} },
		{ ARM64_REG_B9,		{ ARM64_REG_V9,		0,		1	} },

		{ ARM64_REG_V10,	{ ARM64_REG_V10,	0,		16	} },
		{ ARM64_REG_Q10,	{ ARM64_REG_V10,	0,		16	} },  // alias v10 = q10
		{ ARM64_REG_D10,	{ ARM64_REG_V10,	0,		8	} },
		{ ARM64_REG_S10,	{ ARM64_REG_V10,	0,		4	} },
		{ ARM64_REG_H10,	{ ARM64_REG_V10,	0,		2	} },
		{ ARM64_REG_B10,	{ ARM64_REG_V10,	0,		1	} },

		{ ARM64_REG_V11,	{ ARM64_REG_V11,	0,		16	} },
		{ ARM64_REG_Q11,	{ ARM64_REG_V11,	0,		16	} },  // alias v11 = q11
		{ ARM64_REG_D11,	{ ARM64_REG_V11,	0,		8	} },
		{ ARM64_REG_S11,	{ ARM64_REG_V11,	0,		4	} },
		{ ARM64_REG_H11,	{ ARM64_REG_V11,	0,		2	} },
		{ ARM64_REG_B11,	{ ARM64_REG_V11,	0,		1	} },

		{ ARM64_REG_V12,	{ ARM64_REG_V12,	0,		16	} },
		{ ARM64_REG_Q12,	{ ARM64_REG_V12,	0,		16	} },  // alias v12 = q12
		{ ARM64_REG_D12,	{ ARM64_REG_V12,	0,		8	} },
		{ ARM64_REG_S12,	{ ARM64_REG_V12,	0,		4	} },
		{ ARM64_REG_H12,	{ ARM64_REG_V12,	0,		2	} },
		{ ARM64_REG_B12,	{ ARM64_REG_V12,	0,		1	} },

		{ ARM64_REG_V13,	{ ARM64_REG_V13,	0,		16	} },
		{ ARM64_REG_Q13,	{ ARM64_REG_V13,	0,		16	} },  // alias v13 = q13
		{ ARM64_REG_D13,	{ ARM64_REG_V13,	0,		8	} },
		{ ARM64_REG_S13,	{ ARM64_REG_V13,	0,		4	} },
		{ ARM64_REG_H13,	{ ARM64_REG_V13,	0,		2	} },
		{ ARM64_REG_B13,	{ ARM64_REG_V13,	0,		1	} },

		{ ARM64_REG_V14,	{ ARM64_REG_V14,	0,		16	} },
		{ ARM64_REG_Q14,	{ ARM64_REG_V14,	0,		16	} },  // alias v14 = q14
		{ ARM64_REG_D14,	{ ARM64_REG_V14,	0,		8	} },
		{ ARM64_REG_S14,	{ ARM64_REG_V14,	0,		4	} },
		{ ARM64_REG_H14,	{ ARM64_REG_V14,	0,		2	} },
		{ ARM64_REG_B14,	{ ARM64_REG_V14,	0,		1	} },

		{ ARM64_REG_V15,	{ ARM64_REG_V15,	0,		16	} },
		{ ARM64_REG_Q15,	{ ARM64_REG_V15,	0,		16	} },  // alias v15 = q15
		{ ARM64_REG_D15,	{ ARM64_REG_V15,	0,		8	} },
		{ ARM64_REG_S15,	{ ARM64_REG_V15,	0,		4	} },
		{ ARM64_REG_H15,	{ ARM64_REG_V15,	0,		2	} },
		{ ARM64_REG_B15,	{ ARM64_REG_V15,	0,		1	} },

		{ ARM64_REG_V16,	{ ARM64_REG_V16,	0,		16	} },
		{ ARM64_REG_Q16,	{ ARM64_REG_V16,	0,		16	} },  // alias v16 = q16
		{ ARM64_REG_D16,	{ ARM64_REG_V16,	0,		8	} },
		{ ARM64_REG_S16,	{ ARM64_REG_V16,	0,		4	} },
		{ ARM64_REG_H16,	{ ARM64_REG_V16,	0,		2	} },
		{ ARM64_REG_B16,	{ ARM64_REG_V16,	0,		1	} },

		{ ARM64_REG_V17,	{ ARM64_REG_V17,	0,		16	} },
		{ ARM64_REG_Q17,	{ ARM64_REG_V17,	0,		16	} },  // alias v17 = q17
		{ ARM64_REG_D17,	{ ARM64_REG_V17,	0,		8	} },
		{ ARM64_REG_S17,	{ ARM64_REG_V17,	0,		4	} },
		{ ARM64_REG_H17,	{ ARM64_REG_V17,	0,		2	} },
		{ ARM64_REG_B17,	{ ARM64_REG_V17,	0,		1	} },

		{ ARM64_REG_V18,	{ ARM64_REG_V18,	0,		16	} },
		{ ARM64_REG_Q18,	{ ARM64_REG_V18,	0,		16	} },  // alias v18 = q18
		{ ARM64_REG_D18,	{ ARM64_REG_V18,	0,		8	} },
		{ ARM64_REG_S18,	{ ARM64_REG_V18,	0,		4	} },
		{ ARM64_REG_H18,	{ ARM64_REG_V18,	0,		2	} },
		{ ARM64_REG_B18,	{ ARM64_REG_V18,	0,		1	} },

		{ ARM64_REG_V19,	{ ARM64_REG_V19,	0,		16	} },
		{ ARM64_REG_Q19,	{ ARM64_REG_V19,	0,		16	} },  // alias v19 = q19
		{ ARM64_REG_D19,	{ ARM64_REG_V19,	0,		8	} },
		{ ARM64_REG_S19,	{ ARM64_REG_V19,	0,		4	} },
		{ ARM64_REG_H19,	{ ARM64_REG_V19,	0,		2	} },
		{ ARM64_REG_B19,	{ ARM64_REG_V19,	0,		1	} },

		{ ARM64_REG_V20,	{ ARM64_REG_V20,	0,		16	} },
		{ ARM64_REG_Q20,	{ ARM64_REG_V20,	0,		16	} },  // alias v20 = q20
		{ ARM64_REG_D20,	{ ARM64_REG_V20,	0,		8	} },
		{ ARM64_REG_S20,	{ ARM64_REG_V20,	0,		4	} },
		{ ARM64_REG_H20,	{ ARM64_REG_V20,	0,		2	} },
		{ ARM64_REG_B20,	{ ARM64_REG_V20,	0,		1	} },

		{ ARM64_REG_V21,	{ ARM64_REG_V21,	0,		16	} },
		{ ARM64_REG_Q21,	{ ARM64_REG_V21,	0,		16	} },  // alias v21 = q21
		{ ARM64_REG_D21,	{ ARM64_REG_V21,	0,		8	} },
		{ ARM64_REG_S21,	{ ARM64_REG_V21,	0,		4	} },
		{ ARM64_REG_H21,	{ ARM64_REG_V21,	0,		2	} },
		{ ARM64_REG_B21,	{ ARM64_REG_V21,	0,		1	} },

		{ ARM64_REG_V22,	{ ARM64_REG_V22,	0,		16	} },
		{ ARM64_REG_Q22,	{ ARM64_REG_V22,	0,		16	} },  // alias v22 = q22
		{ ARM64_REG_D22,	{ ARM64_REG_V22,	0,		8	} },
		{ ARM64_REG_S22,	{ ARM64_REG_V22,	0,		4	} },
		{ ARM64_REG_H22,	{ ARM64_REG_V22,	0,		2	} },
		{ ARM64_REG_B22,	{ ARM64_REG_V22,	0,		1	} },

		{ ARM64_REG_V23,	{ ARM64_REG_V23,	0,		16	} },
		{ ARM64_REG_Q23,	{ ARM64_REG_V23,	0,		16	} },  // alias v23 = q23
		{ ARM64_REG_D23,	{ ARM64_REG_V23,	0,		8	} },
		{ ARM64_REG_S23,	{ ARM64_REG_V23,	0,		4	} },
		{ ARM64_REG_H23,	{ ARM64_REG_V23,	0,		2	} },
		{ ARM64_REG_B23,	{ ARM64_REG_V23,	0,		1	} },

		{ ARM64_REG_V24,	{ ARM64_REG_V24,	0,		16	} },
		{ ARM64_REG_Q24,	{ ARM64_REG_V24,	0,		16	} },  // alias v24 = q24
		{ ARM64_REG_D24,	{ ARM64_REG_V24,	0,		8	} },
		{ ARM64_REG_S24,	{ ARM64_REG_V24,	0,		4	} },
		{ ARM64_REG_H24,	{ ARM64_REG_V24,	0,		2	} },
		{ ARM64_REG_B24,	{ ARM64_REG_V24,	0,		1	} },

		{ ARM64_REG_V25,	{ ARM64_REG_V25,	0,		16	} },
		{ ARM64_REG_Q25,	{ ARM64_REG_V25,	0,		16	} },  // alias v25 = q25
		{ ARM64_REG_D25,	{ ARM64_REG_V25,	0,		8	} },
		{ ARM64_REG_S25,	{ ARM64_REG_V25,	0,		4	} },
		{ ARM64_REG_H25,	{ ARM64_REG_V25,	0,		2	} },
		{ ARM64_REG_B25,	{ ARM64_REG_V25,	0,		1	} },

		{ ARM64_REG_V26,	{ ARM64_REG_V26,	0,		16	} },
		{ ARM64_REG_Q26,	{ ARM64_REG_V26,	0,		16	} },  // alias v26 = q26
		{ ARM64_REG_D26,	{ ARM64_REG_V26,	0,		8	} },
		{ ARM64_REG_S26,	{ ARM64_REG_V26,	0,		4	} },
		{ ARM64_REG_H26,	{ ARM64_REG_V26,	0,		2	} },
		{ ARM64_REG_B26,	{ ARM64_REG_V26,	0,		1	} },

		{ ARM64_REG_V27,	{ ARM64_REG_V27,	0,		16	} },
		{ ARM64_REG_Q27,	{ ARM64_REG_V27,	0,		16	} },  // alias v27 = q27
		{ ARM64_REG_D27,	{ ARM64_REG_V27,	0,		8	} },
		{ ARM64_REG_S27,	{ ARM64_REG_V27,	0,		4	} },
		{ ARM64_REG_H27,	{ ARM64_REG_V27,	0,		2	} },
		{ ARM64_REG_B27,	{ ARM64_REG_V27,	0,		1	} },

		{ ARM64_REG_V28,	{ ARM64_REG_V28,	0,		16	} },
		{ ARM64_REG_Q28,	{ ARM64_REG_V28,	0,		16	} },  // alias v28 = q28
		{ ARM64_REG_D28,	{ ARM64_REG_V28,	0,		8	} },
		{ ARM64_REG_S28,	{ ARM64_REG_V28,	0,		4	} },
		{ ARM64_REG_H28,	{ ARM64_REG_V28,	0,		2	} },
		{ ARM64_REG_B28,	{ ARM64_REG_V28,	0,		1	} },

		{ ARM64_REG_V29,	{ ARM64_REG_V29,	0,		16	} },
		{ ARM64_REG_Q29,	{ ARM64_REG_V29,	0,		16	} },  // alias v29 = q29
		{ ARM64_REG_D29,	{ ARM64_REG_V29,	0,		8	} },
		{ ARM64_REG_S29,	{ ARM64_REG_V29,	0,		4	} },
		{ ARM64_REG_H29,	{ ARM64_REG_V29,	0,		2	} },
		{ ARM64_REG_B29,	{ ARM64_REG_V29,	0,		1	} },

		{ ARM64_REG_V30,	{ ARM64_REG_V30,	0,		16	} },
		{ ARM64_REG_Q30,	{ ARM64_REG_V30,	0,		16	} },  // alias v30 = q30
		{ ARM64_REG_D30,	{ ARM64_REG_V30,	0,		8	} },
		{ ARM64_REG_S30,	{ ARM64_REG_V30,	0,		4	} },
		{ ARM64_REG_H30,	{ ARM64_REG_V30,	0,		2	} },
		{ ARM64_REG_B30,	{ ARM64_REG_V30,	0,		1	} },

		{ ARM64_REG_V31,	{ ARM64_REG_V31,	0,		16	} },
		{ ARM64_REG_Q31,	{ ARM64_REG_V31,	0,		16	} },  // alias v31 = q31
		{ ARM64_REG_D31,	{ ARM64_REG_V31,	0,		8	} },
		{ ARM64_REG_S31,	{ ARM64_REG_V31,	0,		4	} },
		{ ARM64_REG_H31,	{ ARM64_REG_V31,	0,		2	} },
		{ ARM64_REG_B31,	{ ARM64_REG_V31,	0,		1	} }
	};

	// Converts the enum into human-readable format.
	//
	static std::string name( uint8_t _reg )
	{
		// Else lookup the name from capstone.
		//
		return cs_reg_name( get_cs_handle(), _reg );
	}
	
	// Gets the offset<0> and size<1> of the mapping for the given register.
	//
	static constexpr register_mapping resolve_mapping( uint8_t _reg )
	{
		// Try to find the register mapping, if successful return.
		//
		for ( auto& [reg, map] : register_mappings )
			if ( reg == _reg )
				return map;

		// Otherwise return default mapping after making sure it's valid.
		//
		if ( _reg == ARM64_REG_INVALID || _reg >= ARM64_REG_ENDING ) 
			throw std::logic_error( "Invalid register queried." );
		return { arm64_reg( _reg ), 0, 8 };
	}

	// Gets the base register for the given register.
	//
	static constexpr arm64_reg extend( uint8_t _reg )
	{
		return resolve_mapping( _reg ).base_register;
	}

	// Remaps the given register at given specifications.
	//
	static constexpr arm64_reg remap( uint8_t _reg, uint8_t offset, uint8_t size )
	{
        // Extend passed register
        //
        auto base_register = extend( _reg );

        // For each mapping described:
        //
        for ( auto& pair : register_mappings )
        {
            // If matches the specifications, return.
            //
            if ( pair.second.base_register == base_register &&
                 pair.second.offset == offset &&
                 pair.second.size == size )
                return pair.first;
        }

        // If we fail to find, and we're strictly remapping to a full register, return as is.
        //
		if ( offset != 0 ) 
			throw std::logic_error( "Invalid register remapping." );
        return base_register;
	}

	// Checks whether the register is a generic register that is handled.
	//
	static constexpr bool is_generic( uint8_t _reg )
	{
		return std::find_if( std::begin( register_mappings ), std::end( register_mappings ), [ & ] ( auto& pair ) { return pair.first == _reg; } );
	}
}
