#pragma once
#include <string>
#include <vector>
#include <platform.hpp>
#include "operands.hpp"
#include "..\misc\format.hpp"
#include "..\symbolic\operators.hpp"

namespace vtil::arch
{
    // Maximum operand count.
    //
    static constexpr size_t max_operand_count = 4;

    // Describes the way an instruction acceses it's operands and the
    // constraints built around that, such as "immediate only" implied 
    // by the "_imm" suffix.
    //
    enum operand_access : uint8_t
    {
        // Note: 
        // It still is valid to do != write for read and >= write for writes.
        // this operand access type is illegal to use outside of function arguments.
        //
        invalid = 0, 

        // Read group:
        //
        read_imm,
        read_reg,
        read_any,
        read = read_any,

        // Write group: 
        // - Implicit "_reg" as we cannot write into an immediate
        //
        write,
        readwrite
    };
    
    // Instruction descriptors are used to describe each unique instruction 
    // in the VTIL instruction set. This type should be only constructed 
    // as a global constant. For the sake of consistency all operand indices
    // passed to the constructor start from 1. [Ref: branch_operands desc.]
    //
    struct instruction_desc
    {
        // List of all instances, to be filled by the constructor.
        //
        static std::vector<const instruction_desc*> list;

        // Name of the instruction.
        //
        std::string name;

        // List of the access types for each operand.
        //
        std::vector<operand_access> access_types;

        // Index of the operand that determines the instruction's 
        // access size property.
        //
        int access_size_index = 0;

        // Whether the instruction is volatile or not meaning it
        // should not be discarded even if it is no-op or dead.
        //
        bool is_volatile = false;

        // A pointer to the expression operator that describes the
        // operation of this instruction if applicable.
        //
        std::string symbolic_operator = "";

        // List of operands that are thread as branching destinations.
        // - In the constructor version negative indices are used to 
        //   indicate "real" destinations and thus for the sake of 
        //   simplicity indices start from 1.
        //
        std::vector<int> branch_operands_rip = {};
        std::vector<int> branch_operands_vip = {};

        // Operand that marks the beginning of a memory reference and whether
        // it writes to the pointer or not. [Idx] must be a register and [Idx+1]
        // must be an immediate.
        //
        int memory_operand_index = -1;
        bool memory_write = false;

        // Constructor of this structure will push a reference to
        // itself up the global ::list, which implies any construction
        // should take place in a global context.
        //
        instruction_desc( const std::string& name,
                          const std::vector<operand_access>& access_types,
                          int access_size_index,
                          bool is_volatile,
                          const std::string& symbolic_operator,
                          std::vector<int> branch_operands,
                          const std::pair<int, bool>& memory_operands ) :
            name( name ), access_types( access_types ), access_size_index( access_size_index - 1 ),
            is_volatile( is_volatile ), symbolic_operator( symbolic_operator ),
            memory_operand_index( memory_operands.first - 1 ), memory_write( memory_operands.second )
        {
            list.push_back( this );
            fassert( operand_count() <= max_operand_count );

            // Validate all operand indices.
            //
            fassert( access_size_index == 0 || abs( access_size_index ) <= operand_count() );
            fassert( memory_operands.first == 0 || abs( memory_operands.first ) <= operand_count() );
            for ( int op : branch_operands )
                fassert( op != 0 && abs( op ) <= operand_count() );

            // Process branch operands.
            //
            for ( int op : branch_operands )
            {
                if ( op > 0 )
                    branch_operands_vip.push_back( op - 1 );
                else
                    branch_operands_rip.push_back( -op - 1 );
            }
        }

        // Number of operands this instruction has.
        //
        int operand_count() const { return access_types.size(); }

        // Whether the instruction branches for not.
        //
        bool is_branching_virt() const { return !branch_operands_vip.empty(); }
        bool is_branching_real() const { return !branch_operands_rip.empty(); }
        bool is_branching() const { return is_branching_virt() || is_branching_real(); }

        // Whether the instruction acceses/reads/writes memory or not.
        //
        bool reads_memory() const { return accesses_memory() && !memory_write; }
        bool writes_memory() const { return accesses_memory() && memory_write; }
        bool accesses_memory() const { return memory_operand_index != -1; }

        // Conversion to human-readable format.
        //
        std::string to_string( uint8_t access_size ) const
        {
            if ( !access_size ) return name;
            return name + ( char ) format::suffix_map[ access_size ];
        }
    };
    std::vector<const instruction_desc*> instruction_desc::list = {};
    
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

        //  -- Control flow instructions
        //                                                            
        //    JS         Reg,    Reg/Imm,    Reg/Imm                        | Jumps to OP3 if OP1 != 0, else jumps to OP2, continues virtual execution
        //    JMP        Reg/Imm                                            | Jumps to OP1, continues virtual execution
        //    VEXIT      Reg/Imm                                            | Jumps to OP1, continues real execution
        //    VXCALL     Reg/Imm                                            | Calls into OP1, pauses virtual execution until the call returns
        //
        /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
        /*                                          [Name]        [Operands...]                                     [ASizeOp]   [Volatile]  [Operator]  [BranchOps] [MemOps]     */
        static const instruction_desc js =         { "js",        { read_reg,      read_any,        read_any    },  2,          true,            {},    { 1, 2 },    {}          };
        static const instruction_desc jmp =        { "jmp",       { read_any                                    },  1,          true,            {},    { 1 },       {}          };
        static const instruction_desc vexit =      { "vexit",     { read_any                                    },  1,          true,            {},    { -1 },      {}          };
        static const instruction_desc vxcall =     { "vxcall",    { read_any                                    },  1,          true,            {},    {},          {}          };
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
};