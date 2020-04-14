#include "disassembly.hpp"
#pragma comment(lib, "capstone.lib")

namespace capstone
{
	csh get_handle()
	{
		// Capstone engine is not created until the first call.
		//
		static csh handle = [ ] ()
		{
			csh handle;
			if ( !cs_open( CS_ARCH_X86, CS_MODE_64, &handle ) ||
				 !cs_option( handle, CS_OPT_DETAIL, CS_OPT_ON ) )
				throw std::exception( "Failed to create the Capstone engine!" );
			return handle;
		}( );
		return handle;
	}

	std::vector<vtil::x86::instruction> disasm( const void* bytes, uint64_t address, size_t size, size_t count )
	{
		// Disasemble the instruction.
		//
		cs_insn* ins;
		count = cs_disasm
		(
			get_handle(),
			( uint8_t* ) bytes,
			size ? size : -1,
			address,
			size ? 0 : count,
			&ins
		);

		// Convert each output into vtil::x86 format and push it to a vector.
		//
		std::vector<vtil::x86::instruction> vec;
		for ( int i = 0; i < count; i++ )
		{
			vtil::x86::instruction out;
			cs_insn& in = ins[ i ];

			// Copy cs_insn base.
			//
			out.id = in.id;
			out.address = in.address;
			out.mnemonic = in.mnemonic;
			out.operand_string = in.op_str;
			out.bytes = { in.bytes, in.bytes + in.size };

			// Copy cs_insn::detail.
			//
			out.regs_read = { in.detail->regs_read, in.detail->regs_read + in.detail->regs_read_count };
			out.regs_write = { in.detail->regs_write, in.detail->regs_write + in.detail->regs_write_count };
			out.groups = { in.detail->groups, in.detail->groups + in.detail->groups_count };

			// Copy cs_insn::detail::x86.
			//
			std::copy( std::begin( in.detail->x86.prefix ), std::end( in.detail->x86.prefix ), out.prefix );
			for ( int i = 0; i < 4 && in.detail->x86.opcode[ i ] != 0x0; i++ )
				out.opcode.push_back( in.detail->x86.opcode[ i ] );
			out.rex = in.detail->x86.rex;
			out.addr_size = in.detail->x86.addr_size;
			out.modrm = in.detail->x86.modrm;
			out.sib = in.detail->x86.sib;
			out.disp = in.detail->x86.disp;
			out.sib_index = in.detail->x86.sib_index;
			out.sib_scale = in.detail->x86.sib_scale;
			out.sib_base = in.detail->x86.sib_base;
			out.xop_cc = in.detail->x86.xop_cc;
			out.sse_cc = in.detail->x86.sse_cc;
			out.avx_cc = in.detail->x86.avx_cc;
			out.avx_sae = in.detail->x86.avx_sae;
			out.avx_rm = in.detail->x86.avx_rm;
			out.eflags = in.detail->x86.eflags;
			out.operands = { in.detail->x86.operands, in.detail->x86.operands + in.detail->x86.op_count };
			out.encoding = in.detail->x86.encoding;

			// Push it to up the vector.
			//
			vec.push_back( std::move( out ) );
		}

		// Free the output from Capstone and return the vector.
		//
		cs_free( ins, count );
		return vec;
	}

};