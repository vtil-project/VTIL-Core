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
#include "istack_ref_substitution_pass.hpp"

namespace vtil::optimizer 
{
	// Implement the pass.
	//
	size_t istack_ref_substitution_pass::pass( basic_block* blk, bool xblock )
	{
		size_t counter = 0;
		cached_tracer ctrace = {};

		// For each instruction:
		//
		for ( auto it = blk->begin(); !it.is_end(); it++ )
		{
			// Skip volatile instructions.
			//
			if ( it->is_volatile() ) continue;

			// Filter to instructions that operate with non-sp based pointers.
			//
			if ( it->base->accesses_memory() && !it->memory_location().first.is_stack_pointer() )
			{
				// Try to simplify pointer to SP + C.
				//
				auto delta = ctrace( { it, it->memory_location().first } ) - ctrace( { it, REG_SP } );

				// If successful, replace the operands.
				//
				if ( auto stack_offset = delta.get<int64_t>() )
				{
					( +it )->operands[ it->base->memory_operand_index ] = { REG_SP };
					( +it )->operands[ it->base->memory_operand_index + 1 ].imm().i64 += *stack_offset;

					// Validate modification and increment counter.
					//
					it->is_valid( true );
					counter++;
				}
			}
		}
		return counter;
	}
}
