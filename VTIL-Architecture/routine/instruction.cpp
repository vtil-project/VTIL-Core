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
#include "instruction.hpp"
#include <algorithm>

namespace vtil
{
	// Returns whether the instruction is valid or not.
	//
	bool vtil::instruction::is_valid() const
	{
		// Instruction must have a base descriptor assigned.
		//
		if ( !base )
			return false;

		// Validate operand count.
		//
		if ( operands.size() != base->operand_count() )
			return false;

		// Validate operand types against the base access type.
		//
		for ( int i = 0; i < base->access_types.size(); i++ )
		{
			if ( !operands[ i ].is_valid() )
				return false;
			if ( base->access_types[ i ] == operand_access::read_imm && !operands[ i ].is_immediate() )
				return false;
			if ( base->access_types[ i ] == operand_access::read_reg && !operands[ i ].is_register() )
				return false;
		}

		// Validate memory operands.
		//
		if ( base->accesses_memory() )
		{
			const operand& mem_base = operands[ base->memory_operand_index ];
			const operand& mem_offset = operands[ base->memory_operand_index + 1 ];
			if ( !mem_base.is_register() || mem_base.size() != 8 )
				return false;
			if ( !mem_offset.is_immediate() )
				return false;
		}

		// Validate branching operands.
		//
		for ( auto& list : { base->branch_operands_rip, base->branch_operands_vip } )
		{
			for ( int idx : list )
			{
				if ( operands[ idx ].size() != 8 )
					return false;
			}
		}
		return true;
	}

	// Returns all memory accesses matching the criteria.
	//
	std::pair<register_desc, int64_t> instruction::get_mem_loc( operand_access access ) const
	{
		// Validate arguments.
		//
		fassert( access == operand_access::invalid || access == operand_access::read || access == operand_access::write );

		// If instruction does access memory:
		//
		if ( base->accesses_memory() )
		{
			// Fetch and validate memory operands pair.
			//
			const register_desc& mem_base = operands[ base->memory_operand_index ].reg;
			const operand& mem_offset = operands[ base->memory_operand_index + 1 ];

			if ( !base->memory_write && ( access == operand_access::read || access == operand_access::invalid ) )
				return { mem_base, mem_offset.imm.i64 };
			else if ( base->memory_write && ( access == operand_access::write || access == operand_access::invalid ) )
				return { mem_base, mem_offset.imm.i64 };
		}
		return {};
	}

	// Checks whether the instruction reads from the given register or not.
	//
	int instruction::reads_from( const register_desc& rw ) const
	{
		for ( int i = 0; i < base->access_types.size(); i++ )
			if ( base->access_types[ i ] != operand_access::write && operands[ i ].reg.overlaps( rw ) )
				return i + 1;
		return 0;
	}

	// Checks whether the instruction writes to the given register or not.
	//
	int instruction::writes_to( const register_desc& rw ) const
	{
		for ( int i = 0; i < base->access_types.size(); i++ )
			if ( base->access_types[ i ] >= operand_access::write && operands[ i ].reg.overlaps( rw ) )
				return i + 1;
		return 0;
	}

	// Checks whether the instruction overwrites the given register or not.
	//
	int instruction::overwrites( const register_desc& rw ) const
	{
		for ( int i = 0; i < base->access_types.size(); i++ )
			if ( base->access_types[ i ] == operand_access::write && operands[ i ].reg.overlaps( rw ) )
				return i + 1;
		return 0;
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

	// Generates a hash for the instruction.
	//
	hash_t instruction::hash() const
	{
		hash_t value;

		value << base->name
			  << vip
			  << sp_offset
			  << sp_index
			  << sp_reset
			  << explicit_volatile;

		for ( auto& operand : operands )
			value << operand.hash();

		return value;
	}
};
