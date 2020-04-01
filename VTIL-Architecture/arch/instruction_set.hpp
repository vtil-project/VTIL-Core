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
	constexpr size_t max_operand_count = 4;

	// Describes the way an instruction acceses it's operands and the
	// constraints built around that, such as "immediate only" implied 
	// by the "_imm" suffix.
	//
	enum operand_access
	{
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
	// as a global constant.
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
		const symbolic::operator_desc* symbolic_operator = nullptr;

		// List of operands that are thread as branching destinations.
		// - Negative indices are used to indicate "real" destinations
		//   and thus for the sake of simplicity indices start from 1.
		//
		std::vector<int> branch_operands = {};

		// Constructor of this structure will push a reference to
		// itself up the global ::list, which implies any construction
		// should take place in a global context.
		//
		instruction_desc( std::string name,
						  std::vector<operand_access> access_types,
						  int access_size_index,
						  bool is_volatile,
						  const symbolic::operator_desc* symbolic_operator,
						  std::vector<int> branch_operands ) :
			name( name ), access_types( access_types ), access_size_index( access_size_index ),
			is_volatile( is_volatile ), symbolic_operator( symbolic_operator ), branch_operands( branch_operands )
		{
			list.push_back( this );
			fassert( operand_count() <= max_operand_count );
		}

		// Number of operands this instruction has.
		//
		int operand_count() const { return access_types.size(); }

		// Whether the instruction branches for not.
		//
		bool is_branching() const { return branch_operands.size(); }

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
		using namespace vtil::symbolic;

		//  -- Data/Memory instructions
		//
		//	MOV		Reg,	Reg/Imm									 | OP1 = OP2
		//	MOVR	Reg,	Imm										 | OP1 = Relocate(OP2)
		//	STR		Reg,	Imm,	Reg/Imm							 | [OP1+OP2] <= OP3
		//	LDD		Reg,	Reg,	Imm								 | OP1 <= [OP2+OP3]
		//
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/
		/*										  [Name]		[Operands...]								     [ASizeOp]	  [Volatile]		[Operator]	[BranchOps]*/
		static const instruction_desc mov =		{ "mov",		{ write,		read_any					 },		1,			false,			nullptr,	{}			};
		static const instruction_desc movr =	{ "movr",		{ write,		read_imm					 },		1,			false,			nullptr,	{}			};
		static const instruction_desc str =		{ "str",		{ read_reg,		read_imm,		read_any	 },		2,			false,			nullptr,	{}			};
		static const instruction_desc ldd =		{ "ldd",		{ write,		read_reg,		read_imm	 },		0,			false,			nullptr,	{}			};
		/*--------------------------------------------------------------------------------------------------------------------------------------------------------------*/

		//	-- Arithmetic instructions
		//
		//	NEG		Reg												 | OP1 = -OP1
		//	ADD		Reg,	Reg/Imm									 | OP1 = OP1 + OP2
		//	SUB		Reg,	Reg/Imm									 | OP1 = OP1 - OP2
		//	MUL		Reg,	Reg										 | [OP2:OP1] = OP1 * OP2								
		//	IMUL	Reg,	Reg										 | [OP2:OP1] = OP1 * OP2 (Signed)				
		//	DIV		Reg,	Reg,	Reg/Imm							 | [OP1:OP2]/OP3, Quotient => OP1  Remainder => OP2	
		//	IDIV	Reg,	Reg,	Reg/Imm							 | [OP1:OP2]/OP3, Quotient => OP1  Remainder => OP2	(Signed)
		//
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/
		/*										  [Name]		[Operands...]								     [ASizeOp]	  [Volatile]		[Operator]	[BranchOps]*/
		static const instruction_desc neg =		{ "neg",		{ readwrite									},		0,			false,			&op::neg,	{}			};
		static const instruction_desc add =		{ "add",		{ readwrite,	read_any					},		0,			false,			&op::add,	{}			};
		static const instruction_desc sub =		{ "sub",		{ readwrite,	read_any					},		0,			false,			&op::sub,	{}			};
		static const instruction_desc div =		{ "div",		{ readwrite,	readwrite,		read_any	},		0,			false,			nullptr,	{}			};
		static const instruction_desc idiv =	{ "idiv",		{ readwrite,	readwrite,		read_any	},		0,			false,			nullptr,	{}			};
		static const instruction_desc mul =		{ "mul",		{ readwrite,	readwrite					},		0,			false,			nullptr,	{}			};
		static const instruction_desc imul =	{ "imul",		{ readwrite,	readwrite					},		0,			false,			nullptr,	{}			};
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/
	
		//  -- Bitwise instructions
		//
		//	NOT		Reg												 | OP1 = ~OP1
		//	SHR		Reg,	Reg/Imm									 | OP1 >>= OP2
		//	SHL		Reg,	Reg/Imm									 | OP1 <<= OP2
		//	XOR		Reg,	Reg/Imm									 | OP1 ^= OP2
		//	OR		Reg,	Reg/Imm									 | OP1 |= OP2
		//	AND		Reg,	Reg/Imm									 | OP1 &= OP2
		//	ROR		Reg,	Reg/Imm									 | OP1 = (OP1>>OP2) | (OP1<<(N-OP2))
		//	ROL		Reg,	Reg/Imm									 | OP1 = (OP1<<OP2) | (OP1>>(N-OP2))
		//
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/
		/*										  [Name]		[Operands...]								     [ASizeOp]	  [Volatile]		[Operator]	[BranchOps]*/
		static const instruction_desc bnot =	{ "not",		{ readwrite									},		0,			false,			&op::bnot,	{}			};
		static const instruction_desc bshr =	{ "shr",		{ readwrite,	read_any					},		0,			false,			&op::bshr,	{}			};
		static const instruction_desc bshl =	{ "shl",		{ readwrite,	read_any					},		0,			false,			&op::bshl,	{}			};
		static const instruction_desc bxor =	{ "xor",		{ readwrite,	read_any					},		0,			false,			&op::bxor,	{}			};
		static const instruction_desc bor =		{ "or",			{ readwrite,	read_any					},		0,			false,			&op::bor,	{}			};
		static const instruction_desc band =	{ "and",		{ readwrite,	read_any					},		0,			false,			&op::band,	{}			};
		static const instruction_desc bror =	{ "ror",		{ readwrite,	read_any					},		0,			false,			&op::bror,	{}			};
		static const instruction_desc brol =	{ "rol",		{ readwrite,	read_any					},		0,			false,			&op::brol,	{}			};
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/

		//  -- Control flow instructions
		//															
		//	JS		Reg,	Reg/Imm,	Reg/Imm						| Jumps to OP3 if OP1 != 0, else jumps to OP2, continues virtual execution
		//	JMP		Reg/Imm											| Jumps to OP1, continues virtual execution
		//	VEXIT	Reg/Imm											| Jumps to OP1, continues real execution
		//	VXCALL	Reg/Imm											| Calls into OP1, pauses virtual execution until the call returns
		//
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/
		/*										  [Name]		[Operands...]								     [ASizeOp]	  [Volatile]		[Operator]	[BranchOps]*/
		static const instruction_desc js =		{ "js",			{ read_reg,		read_any,	read_any		},		1,			true,			nullptr,	{ 1, 2 }	};
		static const instruction_desc jmp =		{ "jmp",		{ read_any									},		0,			true,			nullptr,	{ 1 }		};
		static const instruction_desc vexit =	{ "vexit",		{ read_any									},		0,			true,			nullptr,	{ -1 }		};
		static const instruction_desc vxcall =	{ "vxcall",		{ read_any									},		0,			true,			nullptr,	{}			};
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/

		//	-- Special instructions
		//
		//	NOP														| Placeholder
		//	VCMP0		Reg,	Reg									| Compares register against 0 and writes RFLAGS to the OP2
		//  VSETCC		Reg,	Imm									| Emits SETcc on OP1 based on the [OP2]th bit of RFLAGS
		//	VEMIT		Imm											| Emits the x86 opcode
		//	VPINR		Reg											| Pins the register for read
		//	VPINW		Reg											| Pins the register for write
		//  VHMEMV													| Hints the optimzier that all memory including stack is volatile after this instruction
		//	VHSPSH		Imm											| Hints the stack normalizer that at this point stack will be shifted by N
		//
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/
		/*										  [Name]		[Operands...]								     [ASizeOp]	  [Volatile]		[Operator]	[BranchOps]*/
		static const instruction_desc nop =		{ "nop",		{											},		0,			false,			nullptr,	{}			};
		static const instruction_desc vcmp0 =	{ "vcmp0",		{ read_reg,		write						},		0,			false,			nullptr,	{}			};
		static const instruction_desc vsetcc =	{ "vsetcc",		{ write,		read_imm					},		0,			false,			nullptr,	{}			};
		static const instruction_desc vemit =	{ "vemit",		{ read_imm									},		0,			true,			nullptr,	{}			};
		static const instruction_desc vpinr =	{ "vpinr",		{ read_reg									},		0,			true,			nullptr,	{}			};
		static const instruction_desc vpinw =	{ "vpinw",		{ write										},		0,			true,			nullptr,	{}			};
		static const instruction_desc vhmemv =	{ "vhmemv",		{											},		0,			true,			nullptr,	{}			};
		static const instruction_desc vhspsh =	{ "vhspsh",		{ read_imm									},		0,			true,			nullptr,	{}			};
		/*-------------------------------------------------------------------------------------------------------------------------------------------------------------*/
	};
};