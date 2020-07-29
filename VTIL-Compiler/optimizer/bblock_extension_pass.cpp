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
#include "bblock_extension_pass.hpp"

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t bblock_extension_pass::pass( basic_block* blk, bool xblock )
	{
		fassert( xblock );

		// Skip if already visited.
		//
		if ( !visited.emplace( blk ).second )
			return 0;

		// While we can form an extended basic block:
		//
		size_t counter = 0;
		while ( blk->next.size() == 1 &&
				blk->next[ 0 ]->prev.size() == 1 &&
				blk->next[ 0 ] != blk &&
				blk->back().base->is_branching_virt() )
		{
			// Pop the branching instruction.
			//
			blk->pop_back();

			// For each instruction in the destination:
			//
			basic_block* blk_next = blk->next[ 0 ];
			for ( auto& _ins : *blk_next )
			{
				// Make mutable, we don't need to track changes on it anymore since it'll be deleted.
				//
				auto& ins = make_mutable( _ins );

				// For each temporary register used, shift by current maximum:
				//
				for ( operand& op : ins.operands )
					if ( op.is_register() && op.reg().is_local() )
						op.reg().local_id += blk->last_temporary_index;

				// If inherited stack instance:
				//
				if ( ins.sp_index == 0 )
				{
					// Shift stack offset by current offset.
					//
					ins.sp_offset += blk->sp_offset;

					// If memory operation:
					//
					if ( ins.base->accesses_memory() )
					{
						// If base is stack pointer, offset by current offset.
						//
						auto [base, offset] = ins.memory_location();
						if ( base.is_stack_pointer() )
							offset += blk->sp_offset;
					}
				}

				// Shift stack indexes by current maximum and move the instruction to the current block.
				//
				ins.sp_index += blk->sp_index;
				blk->np_emplace_back( std::move( ins ) );
			}

			// Merge block states.
			//
			if ( blk_next->sp_index == 0 )
				blk->sp_offset += blk_next->sp_offset;
			else
				blk->sp_offset = blk_next->sp_offset;
			blk->sp_index += blk_next->sp_index;
			blk->last_temporary_index += blk_next->last_temporary_index;
			blk->next = blk_next->next;

			// Fix the .prev links.
			//
			for ( basic_block* dst : blk_next->next )
				for ( basic_block*& src : dst->prev )
					if ( src == blk_next )
						src = blk;

			// Delete the target block and increment counter.
			//
			blk->owner->delete_block( blk_next );
			counter++;
		}

		// Recurse into destinations:
		//
		for ( auto* dst : blk->next )
			counter += pass( dst, true );
		return counter;
	}
	size_t bblock_extension_pass::xpass( routine* rtn )
	{
		// Invoke recursive optimizer starting from entry point.
		//
		visited.reserve( rtn->explored_blocks.size() );
		size_t n = pass( rtn->entry_point, true );
		if ( n ) symbolic::purge_simplifier_cache();
		return n;
	}
};
