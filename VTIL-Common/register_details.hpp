#pragma once
#include <map>
#include <tuple>
#include <string>
#include "disassembly.hpp"
#include "asserts.hpp"

namespace vtil::x86
{
	// Structure describing how a register maps to another register.
	//
	struct register_mapping
	{
		// Base register of full size, e.g. X86_REG_RAX.
		//
		x86_reg base_register;
		
		// Offset of the current register from the base register.
		//
		uint8_t offset;

		// Size of the current register in bytes.
		//
		uint8_t size;

		inline operator std::tuple<x86_reg, uint8_t, uint8_t>() { return { base_register, offset, size }; }
	};

	// Gets the offset<0> and size<1> of the mapping for the given register.
	//
	register_mapping resolve_mapping( uint8_t _reg );
	
	// Gets the base register for the given register.
	//
	x86_reg extend( uint8_t _reg );

	// Converts the enum into human-readable format.
	//
	std::string name( uint8_t _reg );

	// Remaps the given register at given specifications.
	//
	x86_reg remap( uint8_t _reg, uint8_t offset, uint8_t size );
};