#pragma once
#include <map>
#include <tuple>
#include <capstone.hpp>
#include "control_registers.hpp"

namespace vtil::arch
{
	// List of all physical registers and the base registers they map to <0> at offset <1> of size <2>.
	//
	static const std::map<x86_reg, std::tuple<x86_reg, uint8_t, uint8_t>> register_mappings
	{
		/* [Instance]           [Base]       [Offset] [Size]  */
		{ X86_REG_RAX,		{ X86_REG_RAX,		0,		8	} },
		{ X86_REG_EAX,		{ X86_REG_RAX,		0,		4	} },
		{ X86_REG_AX,		{ X86_REG_RAX,		0,		2	} },
		{ X86_REG_AH,		{ X86_REG_RAX,		1,		1	} },
		{ X86_REG_AL,		{ X86_REG_RAX,		0,		1	} },
						
		{ X86_REG_RBX,		{ X86_REG_RBX,		0,		8	} },
		{ X86_REG_EBX,		{ X86_REG_RBX,		0,		4	} },
		{ X86_REG_BX,		{ X86_REG_RBX,		0,		2	} },
		{ X86_REG_BH,		{ X86_REG_RBX,		1,		1	} },
		{ X86_REG_BL,		{ X86_REG_RBX,		0,		1	} },
						
		{ X86_REG_RCX,		{ X86_REG_RCX,		0,		8	} },
		{ X86_REG_ECX,		{ X86_REG_RCX,		0,		4	} },
		{ X86_REG_CX,		{ X86_REG_RCX,		0,		2	} },
		{ X86_REG_CH,		{ X86_REG_RCX,		1,		1	} },
		{ X86_REG_CL,		{ X86_REG_RCX,		0,		1	} },
						
		{ X86_REG_RDX,		{ X86_REG_RDX,		0,		8	} },
		{ X86_REG_EDX,		{ X86_REG_RDX,		0,		4	} },
		{ X86_REG_DX,		{ X86_REG_RDX,		0,		2	} },
		{ X86_REG_DH,		{ X86_REG_RDX,		1,		1	} },
		{ X86_REG_DL,		{ X86_REG_RDX,		0,		1	} },
						
		{ X86_REG_RDI,		{ X86_REG_RDI,		0,		8	} },
		{ X86_REG_EDI,		{ X86_REG_RDI,		0,		4	} },
		{ X86_REG_DI,		{ X86_REG_RDI,		0,		2	} },
		{ X86_REG_DIL,		{ X86_REG_RDI,		0,		1	} },
						
		{ X86_REG_RSI,		{ X86_REG_RSI,		0,		8	} },
		{ X86_REG_ESI,		{ X86_REG_RSI,		0,		4	} },
		{ X86_REG_SI,		{ X86_REG_RSI,		0,		2	} },
		{ X86_REG_SIL,		{ X86_REG_RSI,		0,		1	} },
						
		{ X86_REG_RBP,		{ X86_REG_RBP,		0,		8	} },
		{ X86_REG_EBP,		{ X86_REG_RBP,		0,		4	} },
		{ X86_REG_BP,		{ X86_REG_RBP,		0,		2	} },
		{ X86_REG_BPL,		{ X86_REG_RBP,		0,		1	} },
						
		{ X86_REG_RSP,		{ X86_REG_RSP,		0,		8	} },
		{ X86_REG_ESP,		{ X86_REG_RSP,		0,		4	} },
		{ X86_REG_SP,		{ X86_REG_RSP,		0,		2	} },
		{ X86_REG_SPL,		{ X86_REG_RSP,		0,		1	} },
						
		{ X86_REG_R8,		{ X86_REG_R8,		0,		8	} },
		{ X86_REG_R8D,		{ X86_REG_R8,		0,		4	} },
		{ X86_REG_R8W,		{ X86_REG_R8,		0,		2	} },
		{ X86_REG_R8B,		{ X86_REG_R8,		0,		1	} },
						
		{ X86_REG_R9,		{ X86_REG_R9,		0,		8	} },
		{ X86_REG_R9D,		{ X86_REG_R9,		0,		4	} },
		{ X86_REG_R9W,		{ X86_REG_R9,		0,		2	} },
		{ X86_REG_R9B,		{ X86_REG_R9,		0,		1	} },

		{ X86_REG_R10,		{ X86_REG_R10,		0,		8	} },
		{ X86_REG_R10D,		{ X86_REG_R10,		0,		4	} },
		{ X86_REG_R10W,		{ X86_REG_R10,		0,		2	} },
		{ X86_REG_R10B,		{ X86_REG_R10,		0,		1	} },

		{ X86_REG_R11,		{ X86_REG_R11,		0,		8	} },
		{ X86_REG_R11D,		{ X86_REG_R11,		0,		4	} },
		{ X86_REG_R11W,		{ X86_REG_R11,		0,		2	} },
		{ X86_REG_R11B,		{ X86_REG_R11,		0,		1	} },

		{ X86_REG_R12,		{ X86_REG_R12,		0,		8	} },
		{ X86_REG_R12D,		{ X86_REG_R12,		0,		4	} },
		{ X86_REG_R12W,		{ X86_REG_R12,		0,		2	} },
		{ X86_REG_R12B,		{ X86_REG_R12,		0,		1	} },

		{ X86_REG_R13,		{ X86_REG_R13,		0,		8	} },
		{ X86_REG_R13D,		{ X86_REG_R13,		0,		4	} },
		{ X86_REG_R13W,		{ X86_REG_R13,		0,		2	} },
		{ X86_REG_R13B,		{ X86_REG_R13,		0,		1	} },

		{ X86_REG_R14,		{ X86_REG_R14,		0,		8	} },
		{ X86_REG_R14D,		{ X86_REG_R14,		0,		4	} },
		{ X86_REG_R14W,		{ X86_REG_R14,		0,		2	} },
		{ X86_REG_R14B,		{ X86_REG_R14,		0,		1	} },

		{ X86_REG_R15,		{ X86_REG_R15,		0,		8	} },
		{ X86_REG_R15D,		{ X86_REG_R15,		0,		4	} },
		{ X86_REG_R15W,		{ X86_REG_R15,		0,		2	} },
		{ X86_REG_R15B,		{ X86_REG_R15,		0,		1	} },

		{ X86_REG_EFLAGS,	{ X86_REG_EFLAGS,	0,		8	} },
	};

	// Gets the offset<0> and size<1> of the mapping for the given register.
	//
	template<typename T>
	static std::pair<uint8_t, uint8_t> get_register_mapping( T _reg )
	{
		// Return default mapping if it's a control register.
		//
		if ( _reg > X86_REG_VCR0 )
			return { 0, 8 };

		// Try to find the register mapping, if succesful return if
		//
		auto it = register_mappings.find( ( x86_reg ) _reg );
		if( it != register_mappings.end() )
			return { std::get<1>( it->second ), std::get<2>( it->second ) };
		
		// Otherwise return default mapping after making sure it's valid.
		//
		fassert( _reg != X86_REG_INVALID );
		return { 0, 8 };
	}
	
	// Gets the base register for the given register.
	//
	template<typename T>
	static x86_reg extend_register( T _reg )
	{
		// Try to find the register mapping, 
		// return as is if we fail to do so.
		//
		auto it = register_mappings.find( ( x86_reg ) _reg );
		if ( it == register_mappings.end() )
			return ( x86_reg ) _reg;
		
		// Otherwise return the base register.
		//
		return std::get<0>( it->second );
	}

	// Converts the enum into human-readable format.
	//
	template<typename T>
	static std::string name_register( T _reg )
	{
		// Return control register name if it's one.
		//
		if ( _reg >= X86_REG_VCR0 )
			return lookup_control_register( ( x86_reg ) _reg )->identifier;
		
		// Else lookup the name from capstone.
		//
		return cs_reg_name( disasm, ( x86_reg ) _reg );
	}

	// Remaps the given register at given specifications.
	//
	template<typename T>
	static x86_reg remap_register( T _reg, uint8_t offset, uint8_t size )
	{
		// Extend passed register
		//
		x86_reg base_register = extend_register( _reg );

		// For each mapping described:
		//
		for ( auto& pair : register_mappings )
		{
			// If matches the specifications, return.
			//
			if ( std::get<0>( pair.second ) == base_register &&
				 std::get<1>( pair.second ) == offset &&
				 std::get<2>( pair.second ) == size )
				return pair.first;
		}

		// If we fail to find, and we're strictly
		// remapping to a full register, return as is.
		//
		fassert( offset == 0  && size == 8);
		return base_register;
	}
};