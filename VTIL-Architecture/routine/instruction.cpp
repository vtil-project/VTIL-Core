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
#include "instruction.hpp"
#include <algorithm>

namespace vtil
{
	// Returns whether the instruction is valid or not.
	//
	bool instruction::is_valid( bool force ) const
	{
#define validate(...) { if( force ) fassert(__VA_ARGS__); else if( !(__VA_ARGS__) ) return false; }

		// Instruction must have a base descriptor assigned.
		//
		validate( base );

		// Validate operand count.
		//
		validate( operands.size() == base->operand_count() );

		// Validate operand types against the expected type.
		//
		for ( int i = 0; i < base->operand_types.size(); i++ )
		{
			validate( operands[ i ].is_valid() );
			validate( base->operand_types[ i ] != operand_type::read_imm || operands[ i ].is_immediate() );
			validate( base->operand_types[ i ] != operand_type::read_reg || operands[ i ].is_register() );
			validate( base->operand_types[ i ] <  operand_type::write || operands[ i ].is_register() );
		}

		// Validate memory operands.
		//
		if ( base->accesses_memory() )
		{
			const operand& mem_base = operands[ base->memory_operand_index ];
			const operand& mem_offset = operands[ base->memory_operand_index + 1 ];
			validate( mem_base.is_register() && mem_base.bit_count() == 64 );
			validate( mem_offset.is_immediate() );
			validate( access_size() && !( access_size() & 7 ) );
		}

		// Validate branching operands.
		//
		for ( auto& list : { base->branch_operands_rip, base->branch_operands_vip } )
			for ( int idx : list )
				validate( operands[ idx ].bit_count() == 64 );
		return true;
#undef validate
	}

	// Returns the memory location this instruction references.
	//
	std::pair<register_desc&, int64_t&> instruction::memory_location()
	{
		// Assert that instruction does access memory.
		//
		fassert( base->accesses_memory() );

		// Reference the pair of operands used to create the pointer and return them.
		//
		return {
			operands[ base->memory_operand_index ].reg(), 
			operands[ base->memory_operand_index + 1 ].imm().i64 
		};
	}
	std::pair<const register_desc&, const int64_t&> instruction::memory_location() const
	{
		// Assert that instruction does access memory.
		//
		fassert( base->accesses_memory() );

		// Reference the pair of operands used to create the pointer and return them.
		//
		return {
			operands[ base->memory_operand_index ].reg(),
			operands[ base->memory_operand_index + 1 ].imm().i64
		};
	}

	// Conversion to human-readable format.
	//
	std::string instruction::to_string( bool pad_right ) const
	{
		std::string output = format::str( VTIL_FMT_INS_MNM, base->to_string( access_size() ) );
		for ( auto& op : operands )
			output += format::str( " " VTIL_FMT_INS_OPR, op.to_string() );
		if ( pad_right )
		{
			size_t padding_cnt = ( VTIL_ARCH_MAX_OPERAND_COUNT - operands.size() ) * ( VTIL_FMT_INS_OPR_S + 1 );
			std::fill_n( std::back_inserter( output ), padding_cnt, ' ' );
		}
		return output;
	}
};
