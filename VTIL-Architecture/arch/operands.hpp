#pragma once
#include <string>
#include <capstone.hpp>
#include "registers.hpp"
#include "..\misc\format.hpp"

// Any operand used in a VTIL instruction will be essentialy either a register or an 
// immediate value, where registers can also be either temporaries, physical registers or 
// control registers.
//
//  - 1) Immediate value
//  - 2) Register
//	  - a) Temporaries
//	  - b) Physical registers
//	  - c) Control registers
//
namespace vtil::arch
{
	// The operand structure that is used to describe operands of an instruction.
	//
	struct operand
	{
		// If operand is a register:
		//
		register_view reg = {};

		// If operand is an immediate:
		//
		union
		{
			uint64_t u64 = 0;
			int64_t i64;
		};
		uint8_t imm_size = 0;

		// Operand type is constructed either by a register view or an immediate
		// followed by an explicit size.
		//
		operand() {}
		operand( const register_view& rw ) : reg( rw ), imm_size( 0 ) {}
		operand( uint64_t v, uint8_t size ) : u64( v ), imm_size( size ) {}

		// Getter for the operand size.
		//
		uint8_t size() const { return is_immediate() ? imm_size : reg.size; }

		// Conversion to human-readable format.
		//
		std::string to_string() const { return is_register() ? reg.to_string() : format::hex( i64 ); }

		// Simple helpers to determine the type of operand.
		//
		bool is_register() const { return reg.is_valid(); }
		bool is_immediate() const { return imm_size != 0; }
		bool is_valid() const { return is_register() || is_immediate(); }

		// Basic comparison operators.
		//
		bool operator!=( const operand& o ) const { return !operator==( o ); };
		bool operator==( const operand& o ) const { return is_register() ? reg == o.reg : imm_size == o.imm_size && u64 == o.u64; }
		bool operator<( const operand& o ) const { return is_register() ? reg < o.reg : ( imm_size == o.imm_size ? u64 < o.u64 : imm_size < o.imm_size ); }
	};
};