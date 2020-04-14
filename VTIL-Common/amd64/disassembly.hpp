#pragma once
#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <set>
#include <capstone/capstone.h>
#include "..\io\formatting.hpp"

namespace vtil::x86
{
	struct instruction
	{
		// Data copied from base of [cs_insn].
		//
		uint32_t id = 0;
		uint64_t address = 0;
		std::vector<uint8_t> bytes;
		std::string mnemonic;
		std::string operand_string;

		// Data copied from [cs_insn::detail].
		//
		std::set<uint16_t> regs_read;
		std::set<uint16_t> regs_write;
		std::set<uint8_t> groups;

		// Data copied from [cs_insn::detail::x86]
		//
		uint8_t prefix[ 4 ];
		std::vector<uint8_t> opcode;
		
		uint8_t rex;
		uint8_t addr_size;
		uint8_t modrm;
		uint8_t sib;
		int64_t disp;
		
		x86_reg sib_index;
		int8_t sib_scale;
		x86_reg sib_base;

		x86_xop_cc xop_cc;
		x86_sse_cc sse_cc;
		x86_avx_cc avx_cc;

		bool avx_sae;
		x86_avx_rm avx_rm;

		union
		{
			uint64_t eflags;
			uint64_t fpu_flags;
		};

		std::vector<cs_x86_op> operands;
		cs_x86_encoding encoding;

		// Returns human readable disassembly.
		//
		inline std::string dump() const
		{
			return format::str( "%p: %s\t%s", address, mnemonic, operand_string );
		}

		// Helper to check if instruction is of type <x86_INS_*, {X86_OP_*...}>.
		//
		inline bool is( uint32_t idx, const std::vector<x86_op_type>& operands_t ) const
		{
			if ( id != idx ) return false;
			if ( operands.size() != operands_t.size() ) return false;
			for ( int i = 0; i < operands.size(); i++ )
				if ( operands[ i ].type != operands_t[ i ] )
					return false;
			return true;
		}

		// Helper to check if instruction belongs to the given group.
		//
		inline bool in_group( uint8_t group_searched ) const
		{
			return std::find( groups.begin(), groups.end(), group_searched ) != groups.end();
		}
	};
};

// Simple wrapper around Capstone disasembler.
//
namespace capstone
{
	csh get_handle();
	std::vector<vtil::x86::instruction> disasm( const void* bytes, uint64_t address, size_t size = 0, size_t count = 1 );
};