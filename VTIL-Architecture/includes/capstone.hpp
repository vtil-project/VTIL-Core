#pragma once
#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <capstone/capstone.h>
#include "platform.hpp"
#pragma comment(lib, "capstone_i.lib")

namespace capstone
{
	struct instruction
	{
		// Base object
		uint32_t id = 0;
		uint64_t address = 0;
		std::vector<uint8_t> bytes;
		std::string mnemonic;
		std::string operand_string;

		// From ->detail
		std::vector<uint16_t> regs_read;
		std::vector<uint16_t> regs_write;
		std::vector<uint8_t> groups;
		cs_x86 details;

		instruction() {};
		instruction( const cs_insn& ins ) :
			id( ins.id ), address( ins.address ),
			mnemonic( ins.mnemonic ), operand_string( ins.op_str ),
			bytes( ins.bytes, ins.bytes + ins.size ),
			regs_read( ins.detail->regs_read, ins.detail->regs_read + ins.detail->regs_read_count ),
			regs_write( ins.detail->regs_write, ins.detail->regs_write + ins.detail->regs_write_count ),
			groups( ins.detail->groups, ins.detail->groups + ins.detail->groups_count ),
			details( ins.detail->x86 )
		{
		}

		std::string dump() const
		{
			char bfr[ 64 ];
			sprintf_s( bfr, "%p: %s\t%s", address, mnemonic.data(), operand_string.data() );
			return bfr;
		}

		bool is( uint32_t idx, const std::vector<x86_op_type>& operands ) const
		{
			if ( id != idx ) return false;
			if ( details.op_count != operands.size() ) return false;
			for ( int i = 0; i < details.op_count; i++ )
				if ( details.operands[ i ].type != operands[ i ] )
					return false;
			return true;
		}

		bool in_group( uint8_t g ) const
		{
			for ( auto o : groups )
				if ( o == g ) return true;
			return false;
		}
	};

	struct context
	{
		csh handle = 0;
		void destroy() { cs_close( &handle ); }

		operator csh() { return handle; }

		std::vector<instruction> operator()( const void* bytes, uint64_t address, size_t size = 0, size_t count = 1 )
		{
			std::vector<instruction> out;

			cs_insn* ins;
			count = cs_disasm
			(
				handle,
				( uint8_t* ) bytes,
				size ? size : -1,
				address,
				size ? 0 : count,
				&ins
			);

			for ( int i = 0; i < count; i++ )
				out.push_back( ins[ i ] );
			cs_free( ins, count );
			return out;
		}
	};

	static context create( cs_arch arch, cs_mode mode )
	{
		context ctx;
		if ( !cs_open( arch, mode, &ctx.handle ) )
			cs_option( ctx.handle, CS_OPT_DETAIL, CS_OPT_ON );
		else
			throw "Failed to create the disassembler!";
		return ctx;
	}
};

static auto disasm = capstone::create( CS_ARCH_X86, CS_MODE_64 );