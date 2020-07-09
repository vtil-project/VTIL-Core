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
#pragma once
#include <string>
#include <set>
#include <vtil/io>
#include <vtil/amd64>
#include "../arch/instruction_set.hpp"
#include "../routine/basic_block.hpp"
#include "../routine/instruction.hpp"

namespace vtil::debug
{
	static void dump( const instruction& ins, const instruction* prev = nullptr )
	{
		using namespace logger;
		
		// Print stack pointer offset
		//
		if ( ins.sp_index )
			log<CON_YLW>( "[%d] ", ins.sp_index );
		else
			log( "    " );

		if ( ins.sp_reset )
			log<CON_PRP>( ">%c0x%-4x ", ins.sp_offset >= 0 ? '+' : '-', abs( ins.sp_offset ) );
		else if ( ( prev ? prev->sp_offset : 0 ) == ins.sp_offset )
			log<CON_DEF>( "%c0x%-4x  ", ins.sp_offset >= 0 ? '+' : '-', abs( ins.sp_offset ) );
		else if ( ( prev ? prev->sp_offset : 0 ) > ins.sp_offset )
			log<CON_RED>( "%c0x%-4x  ", ins.sp_offset >= 0 ? '+' : '-', abs( ins.sp_offset ) );
		else
			log<CON_BLU>( "%c0x%-4x  ", ins.sp_offset >= 0 ? '+' : '-', abs( ins.sp_offset ) );

		// Print name
		//
		if ( ins.is_volatile() )
			log<CON_RED>( VTIL_FMT_INS_MNM " ", ins.base->to_string( ins.access_size() ) );			// Volatile instruction
		else
			log<CON_BRG>( VTIL_FMT_INS_MNM " ", ins.base->to_string( ins.access_size() ) );			// Non-volatile instruction

		// Print each operand
		//
		for ( auto& op : ins.operands )
		{
			if ( op.is_register() )
			{
				if ( op.reg().is_stack_pointer() )
					log<CON_PRP>( VTIL_FMT_INS_OPR " ", op.reg() );									// Stack pointer
				else if ( op.reg().is_physical() )
					log<CON_BLU>( VTIL_FMT_INS_OPR " ", op.reg() );									// Any hardware/special register
				else
					log<CON_GRN>( VTIL_FMT_INS_OPR " ", op.reg() );									// Virtual register
			}
			else
			{
				fassert( op.is_immediate() );

				if ( ins.base->memory_operand_index  != -1 &&
					 &ins.operands[ size_t( ins.base->memory_operand_index ) + 1 ] == &op &&
					 ins.operands[ ins.base->memory_operand_index ].reg().is_stack_pointer() )
				{
					if ( op.imm().i64 >= 0 )
						log<CON_YLW>( VTIL_FMT_INS_OPR " ", format::hex( op.imm().i64 ) );			 // External stack
					else
						log<CON_BRG>( VTIL_FMT_INS_OPR " ", format::hex( op.imm().i64 ) );			 // VM stack
				}
				else
				{
					log<CON_CYN>( VTIL_FMT_INS_OPR " ", format::hex( op.imm().i64 ) );				 // Any immediate
				}
			}
		}

		// End line
		//
		log( "\n" );
	}

	static void dump( const basic_block* blk, std::set<const basic_block*>* visited = nullptr )
	{
		using namespace vtil::logger;
		scope_padding _p( 4 );

		bool blk_visited = visited ? visited->find( blk ) != visited->end() : false;

		auto end_with_bool = [ ] ( bool b )
		{
			if ( b ) log<CON_GRN>( "Y\n" );
			else log<CON_RED>( "N\n" );
		};

		log<CON_DEF>( "Entry point VIP:       " );
		log<CON_CYN>( "0x%llx\n", blk->entry_vip );
		log<CON_DEF>( "Stack pointer:         " );
		if ( blk->sp_offset < 0 )
			log<CON_RED>( "%s\n", format::hex( blk->sp_offset ) );
		else
			log<CON_GRN>( "%s\n", format::hex( blk->sp_offset ) );
		log<CON_DEF>( "Already visited?:      " ); 
		end_with_bool( blk_visited );
		log<CON_DEF>( "------------------------\n" );

		if ( blk_visited )
			return;

		// Print each instruction
		//
		int ins_idx = 0;
		bool no_disasm = false;
		for ( auto it = blk->begin(); it != blk->end(); it++, ins_idx++ )
		{
			// If vemit, try to disassmble if not done already.
			//
			if ( it->base->name == "vemit" )
			{
				if ( !no_disasm )
				{
					std::vector<uint8_t> bytes;
					for ( auto it2 = it; it2 != blk->end(); it2++ )
					{
						if ( it2->base->name != "vemit" )
							break;
						uint8_t* bs = ( uint8_t* ) &it2->operands[ 0 ].imm().u64;
						bytes.insert( bytes.end(), bs, bs + it2->operands[ 0 ].size() );
					}

					if ( bytes.size() )
					{
						if ( it.container->owner->arch_id == architecture_amd64 )
						{
							auto dasm = amd64::disasm( bytes.data(), it->vip == invalid_vip ? 0 : it->vip, bytes.size() );
							for ( auto& ins : dasm )
								log<CON_YLW>( "; %s\n", ins );
						}
						else
						{
							auto dasm = arm64::disasm( bytes.data(), it->vip == invalid_vip ? 0 : it->vip, bytes.size() );
							for ( auto& ins : dasm )
								log<CON_YLW>( "; %s\n", ins );
						}
					}
					no_disasm = true;
				}
			}
			else
			{
				no_disasm = false;
			}

			// Print string context if any.
			//
			if ( it->context.has<std::string>() )
			{
				const std::string& cmt = it->context;
				log<CON_GRN>( "// %s\n", cmt );

				// Skip if nop.
				//
				if ( it->base == &ins::nop ) continue;
			}

			log<CON_BLU>( "%04d: ", ins_idx );
			if ( it->vip == invalid_vip )
				log<CON_DEF>( "[ PSEUDO ] " );
			else
				log<CON_DEF>( "[%08x] ", ( uint32_t ) it->vip );
			dump( *it, it.is_begin() ? nullptr : &*std::prev( it ) );
		}

		// Dump each branch as well
		//
		if ( visited )
		{
			visited->insert( blk );
			for ( auto& child : blk->next )
				dump( child, visited );
		}
	}

	static void dump( const routine* routine )
	{
		std::set<const basic_block*> vs;
		dump( routine->entry_point, &vs );
	}
};