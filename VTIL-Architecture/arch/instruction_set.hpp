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
#include <vector>
#include "instruction_desc.hpp"

namespace vtil::arch
{
    namespace ins
    {
        //  -- Data/Memory instructions
        //
        //    MOV        Reg,    Reg/Imm                                     | OP1 = OP2
        //    MOVR       Reg,    Imm                                         | OP1 = Relocate(OP2)
        //    STR        Reg,    Imm,    Reg/Imm                             | [OP1+OP2] <= OP3
        //    LDD        Reg,    Reg,    Imm                                 | OP1 <= [OP2+OP3]
        //
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
        /*                                          [Name]        [Operands...]                                     [ASizeOp]   [Volatile]  [Operator]  [BranchOps] [MemOps]     */
        static const instruction_desc mov =        { "mov",        { write,        read_any                   },    2,          false,      {},         {},         {}           };
        static const instruction_desc movr =       { "movr",       { write,        read_imm                   },    2,          false,      {},         {},         {}           };
        static const instruction_desc str =        { "str",        { read_reg,     read_imm,        read_any  },    3,          false,      {},         {},         { 1, true }  };
        static const instruction_desc ldd =        { "ldd",        { write,        read_reg,        read_imm  },    1,          false,      {},         {},         { 2, false } };
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

        //    -- Arithmetic instructions
        //
        //    NEG        Reg                                                 | OP1 = -OP1
        //    ADD        Reg,    Reg/Imm                                     | OP1 = OP1 + OP2
        //    SUB        Reg,    Reg/Imm                                     | OP1 = OP1 - OP2
        //    MUL        Reg,    Reg/Imm                                     | OP1 = OP1 * OP2
        //    MULHI      Reg,    Reg/Imm                                     | OP1 = [OP1 * OP2]>>N
        //    IMUL       Reg,    Reg/Imm                                     | OP1 = OP1 * OP2         (Signed)
        //    IMULHI     Reg,    Reg/Imm                                     | OP1 = [OP1 * OP2]>>N    (Signed)
        //    DIV        Reg,    Reg/Imm    Reg/Imm                          | OP1 = [OP2:OP1] / OP3         
        //    REM        Reg,    Reg/Imm                                     | OP1 = OP1 % OP2         
        //    IDIV       Reg,    Reg/Imm    Reg/Imm                          | OP1 = [OP2:OP1] / OP3   (Signed)
        //    IREM       Reg,    Reg/Imm                                     | OP1 = OP1 % OP2         (Signed)
        //
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
        /*                                          [Name]        [Operands...]                                     [ASizeOp]   [Volatile]  [Operator]  [BranchOps] [MemOps]     */
        static const instruction_desc neg =        { "neg",       { readwrite                                 },    1,            false,    "neg",      {},         {}           };
        static const instruction_desc add =        { "add",       { readwrite,     read_any                   },    1,            false,    "add",      {},         {}           };
        static const instruction_desc sub =        { "sub",       { readwrite,     read_any                   },    1,            false,    "sub",      {},         {}           };
        static const instruction_desc mul =        { "mul",       { readwrite,     read_any                   },    1,            false,    {},         {},         {}           };
        static const instruction_desc imul =       { "imul",      { readwrite,     read_any                   },    1,            false,    {},         {},         {}           };
        static const instruction_desc mulhi =      { "mulhi",     { readwrite,     read_any                   },    1,            false,    {},         {},         {}           };
        static const instruction_desc imulhi =     { "imulhi",    { readwrite,     read_any                   },    1,            false,    {},         {},         {}           };
        static const instruction_desc div =        { "div",       { readwrite,     read_any,        read_any  },    1,            false,    {},         {},         {}           };
        static const instruction_desc idiv =       { "idiv",      { readwrite,     read_any,        read_any  },    1,            false,    {},         {},         {}           };
        static const instruction_desc rem =        { "rem",       { readwrite,     read_any,        read_any  },    1,            false,    {},         {},         {}           };
        static const instruction_desc irem =       { "irem",      { readwrite,     read_any,        read_any  },    1,            false,    {},         {},         {}           };
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
    
        //  -- Bitwise instructions
        //
        //    NOT        Reg                                                 | OP1 = ~OP1
        //    SHR        Reg,    Reg/Imm                                     | OP1 >>= OP2
        //    SHL        Reg,    Reg/Imm                                     | OP1 <<= OP2
        //    XOR        Reg,    Reg/Imm                                     | OP1 ^= OP2
        //    OR         Reg,    Reg/Imm                                     | OP1 |= OP2
        //    AND        Reg,    Reg/Imm                                     | OP1 &= OP2
        //    ROR        Reg,    Reg/Imm                                     | OP1 = (OP1>>OP2) | (OP1<<(N-OP2))
        //    ROL        Reg,    Reg/Imm                                     | OP1 = (OP1<<OP2) | (OP1>>(N-OP2))
        //
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
        /*                                          [Name]        [Operands...]                                     [ASizeOp]   [Volatile]  [Operator]  [BranchOps] [MemOps]     */
        static const instruction_desc bnot =        { "not",      { readwrite                                 },    1,          false,      "not",      {},          {}          };
        static const instruction_desc bshr =        { "shr",      { readwrite,     read_any                   },    1,          false,      "shr",      {},          {}          };
        static const instruction_desc bshl =        { "shl",      { readwrite,     read_any                   },    1,          false,      "shl",      {},          {}          };
        static const instruction_desc bxor =        { "xor",      { readwrite,     read_any                   },    1,          false,      "xor",      {},          {}          };
        static const instruction_desc bor =         { "or",       { readwrite,     read_any                   },    1,          false,      "or",       {},          {}          };
        static const instruction_desc band =        { "and",      { readwrite,     read_any                   },    1,          false,      "and",      {},          {}          };
        static const instruction_desc bror =        { "ror",      { readwrite,     read_any                   },    1,          false,      "ror",      {},          {}          };
        static const instruction_desc brol =        { "rol",      { readwrite,     read_any                   },    1,          false,      "rol",      {},          {}          };
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
    
        //  -- Flag-creation instructions
        //
        //    SETS       Reg                                                 | OP1 = EFLAGS(OP2)[SF]
        //    SETZ       Reg                                                 | OP1 = EFLAGS(OP2)[ZF]
        //    SETP       Reg                                                 | OP1 = EFLAGS(OP2)[PF]
        //    SETC       Reg                                                 | OP1 = EFLAGS(OP2)[CF]
        //    SETO       Reg                                                 | OP1 = EFLAGS(OP2)[OF]
                                                                             
        //
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
        /*                                          [Name]        [Operands...]                                     [ASizeOp]   [Volatile]  [Operator]  [BranchOps] [MemOps]     */
        static const instruction_desc sets =        { "sets",     { write,         read_any                   },    1,          false,      "sets",     {},          {}          };
        static const instruction_desc setz =        { "setz",     { write,         read_any                   },    1,          false,      "setz",     {},          {}          };
        static const instruction_desc setp =        { "setp",     { write,         read_any                   },    1,          false,      "setp",     {},          {}          };
        static const instruction_desc setc =        { "setc",     { write,         read_any                   },    1,          false,      "setc",     {},          {}          };
        static const instruction_desc seto =        { "seto",     { write,         read_any                   },    1,          false,      "seto",     {},          {}          };
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

        //  -- Control flow instructions
        //                                                            
        //    JS         Reg,    Reg/Imm,    Reg/Imm                        | Jumps to OP3 if OP1 != 0, else jumps to OP2, continues virtual execution
        //    JMP        Reg/Imm                                            | Jumps to OP1, continues virtual execution
        //    VEXIT      Reg/Imm                                            | Jumps to OP1, continues real execution
        //    VXCALL     Reg/Imm                                            | Calls into OP1, pauses virtual execution until the call returns
        //
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
        /*                                          [Name]        [Operands...]                                     [ASizeOp]   [Volatile]  [Operator]  [BranchOps] [MemOps]     */
        static const instruction_desc js =         { "js",        { read_reg,      read_any,        read_any    },  2,          true,        {},        { 1, 2 },    {}          };
        static const instruction_desc jmp =        { "jmp",       { read_any                                    },  1,          true,        {},        { 1 },       {}          };
        static const instruction_desc vexit =      { "vexit",     { read_any                                    },  1,          true,        {},        { -1 },      {}          };
        static const instruction_desc vxcall =     { "vxcall",    { read_any                                    },  1,          true,        {},        {},          {}          };
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

        //    -- Special instructions
        //
        //    NOP                                                           | Placeholder
        //    VCMP0      Reg,    Reg                                        | Compares register against 0 and writes RFLAGS to the OP2
        //    VSETCC     Reg,    Imm                                        | Emits SETcc on OP1 based on the [OP2]th bit of RFLAGS
        //    VEMIT      Imm                                                | Emits the x86 opcode
        //    VPINR      Reg                                                | Pins the register for read
        //    VPINW      Reg                                                | Pins the register for write
        //    VPINRM     Reg,    Imm                                        | Pins the qword @ memory location for read
        //    VPINWM     Reg,    Imm                                        | Pins the qword @ memory location for write
        //
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
        /*                                          [Name]        [Operands...]                                     [ASizeOp]   [Volatile]  [Operator]  [BranchOps] [MemOps]     */
        static const instruction_desc nop =        { "nop",       {                                             },  0,          false,      {},         {},         {}           };
        static const instruction_desc vcmp0 =      { "vcmp0",     { read_reg,      write                        },  1,          false,      {},         {},         {}           };
        static const instruction_desc vsetcc =     { "vsetcc",    { write,         read_imm                     },  1,          false,      {},         {},         {}           };
        static const instruction_desc vemit =      { "vemit",     { read_imm                                    },  1,          true,       {},         {},         {}           };
        static const instruction_desc vpinr =      { "vpinr",     { read_reg                                    },  1,          true,       {},         {},         {}           };
        static const instruction_desc vpinw =      { "vpinw",     { write                                       },  1,          true,       {},         {},         {}           };
        static const instruction_desc vpinrm =     { "vpinrm",    { read_reg,      read_imm,                    },  1,          true,       {},         {},         { 1, false } };
        static const instruction_desc vpinwm =     { "vpinwm",    { read_reg,      read_imm                     },  1,          true,       {},         {},         { 1, true }  };
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
    };

    // List of all instructions.
    //
    static const instruction_desc* instruction_list[] = 
    {
        &ins::mov, &ins::movr, &ins::str, &ins::ldd, &ins::neg, &ins::add, &ins::sub, &ins::mul,
        &ins::imul, &ins::mulhi, &ins::imulhi, &ins::div, &ins::idiv, &ins::rem, &ins::irem, &ins::bnot,
        &ins::bshr, &ins::bshl, &ins::bxor, &ins::bor, &ins::band, &ins::bror, &ins::brol, &ins::sets,
        &ins::setz, &ins::setp, &ins::setc, &ins::seto, &ins::js, &ins::jmp, &ins::vexit, &ins::vxcall,
        &ins::nop, &ins::vcmp0, &ins::vsetcc, &ins::vemit, &ins::vpinr, &ins::vpinw, &ins::vpinrm, &ins::vpinwm
    };
};