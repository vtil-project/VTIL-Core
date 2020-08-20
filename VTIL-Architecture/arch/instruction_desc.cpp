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
#include "instruction_desc.hpp"

namespace vtil
{
	// Generic data-assignment constructor with certain validity checks.
	//
	instruction_desc::instruction_desc( const std::string& name, 
										const std::vector<operand_type>& operand_types,
										int access_size_index, 
										bool is_volatile, 
										math::operator_id symbolic_operator,
										std::vector<int> branch_operands, 
										const std::pair<int, bool>& memory_operands ) :
		name( name ), operand_types( operand_types ), vaccess_size_index( access_size_index ),
		is_volatile( is_volatile ), symbolic_operator( symbolic_operator ),
		memory_operand_index( memory_operands.first - 1 ), memory_write( memory_operands.second )
	{
		fassert( operand_count() <= VTIL_ARCH_MAX_OPERAND_COUNT );

		// Validate all operand indices.
		//
		fassert( vaccess_size_index == 0 || abs( vaccess_size_index ) <= operand_count() );
		fassert( memory_operands.first == 0 || abs( memory_operands.first ) <= operand_count() );
		for ( int op : branch_operands )
			fassert( op != 0 && abs( op ) <= operand_count() );

		// Validate variable access size.
		//
		if ( vaccess_size_index < 0 )
			fassert( operand_types[ ( -vaccess_size_index ) - 1 ] == operand_type::read_imm );

		// Process branch operands.
		//
		for ( int op : branch_operands )
		{
			if ( op > 0 )
				branch_operands_vip.push_back( op - 1 );
			else
				branch_operands_rip.push_back( -op - 1 );
		}

		// Validate operand types.
		//
		bool written = false;
		for ( operand_type type : operand_types )
		{
			if ( type >= operand_type::write )
			{
				fassert( !written );
				written = true;
			}
		}
	}
};