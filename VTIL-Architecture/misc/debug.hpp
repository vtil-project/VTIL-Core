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
#include <string>
#include <set>
#include <vtil/io>
#include "..\arch\instruction_set.hpp"
#include "..\routine\basic_block.hpp"
#include "..\routine\instruction.hpp"

namespace vtil::debug
{
	static void dump( const instruction& ins, const instruction* prev = nullptr )
	{
		using namespace vtil::logger;
		
		// Print stack pointer offset
		//
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
			log<CON_RED>( FMT_INS_MNM " ", ins.base->to_string( ins.access_size() ) );	// Volatile instruction
		else
			log<CON_BRG>( FMT_INS_MNM " ", ins.base->to_string( ins.access_size() ) );	// Non-volatile instruction

		// Print each operand
		//
		for ( auto& op : ins.operands )
		{
			if ( op.is_register() )
			{
				if ( op.reg.base.maps_to == X86_REG_RSP )
					log<CON_PRP>( FMT_INS_OPR " ", op.reg.to_string() );				// Stack pointer
				else if ( op.reg.base.maps_to != X86_REG_INVALID )
					log<CON_BLU>( FMT_INS_OPR " ", op.reg.to_string() );				// Any hardware/special register
				else
					log<CON_GRN>( FMT_INS_OPR " ", op.reg.to_string() );				// Virtual register
			}
			else
			{
				fassert( op.is_immediate() );

				if ( ins.base->memory_operand_index  != -1 &&
					 &ins.operands[ ins.base->memory_operand_index + 1 ] == &op &&
					 ins.operands[ ins.base->memory_operand_index ].reg == X86_REG_RSP )
				{
					if ( op.i64 >= 0 )
						log<CON_YLW>( FMT_INS_OPR " ", format::hex( op.i64 ) );			 // External stack
					else
						log<CON_BRG>( FMT_INS_OPR " ", format::hex( op.i64 ) );			 // VM stack
				}
				else
				{
					log<CON_CYN>( FMT_INS_OPR " ", format::hex( op.i64 ) );				 // Any immediate
				}
			}
		}

		// Print padding and end line
		//
		fassert( ins.operands.size() <= arch::max_operand_count );
		for ( int i = ins.operands.size(); i < arch::max_operand_count; i++ )
			log( FMT_INS_OPR " ", "" );
		log( "\n" );
	}

	static void dump( const basic_block* blk, std::set<const basic_block*>* visited = nullptr )
	{
		using namespace vtil::logger;

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
		for ( auto it = blk->begin(); it != blk->end(); it++, ins_idx++ )
		{
			log<CON_BLU>( "%04d: ", ins_idx );
			if ( it->vip == invalid_vip )
				log<CON_DEF>( "[PSEUDO] " );
			else
				log<CON_DEF>( "[%06x] ", it->vip );
			dump( *it, it.is_begin() ? nullptr : &*std::prev( it ) );
		}

		// Dump each branch as well
		//
		if ( visited )
		{
			visited->insert( blk );
			log_padding++;
			log( "\n" );
			for ( auto& child : blk->next )
				dump( child, visited );
			log_padding--;
			log( "\n" );
		}
	}

	static void dump( const routine* routine )
	{
		std::set<const basic_block*> vs;
		dump( routine->entry_point, &vs );
	}
};