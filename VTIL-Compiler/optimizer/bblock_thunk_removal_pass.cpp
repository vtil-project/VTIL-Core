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
#include "bblock_thunk_removal_pass.hpp"

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t bblock_thunk_removal_pass::pass(basic_block* blk, bool xblock)
	{
		fassert( xblock );

		// Track at what block we start the recursive fixing.
		// We can only delete blocks just before leaving the function
		//
		if(!first_block)
			first_block = blk;

		// Skip if already visited.
		//
		if ( !visited.emplace( blk ).second )
			return 0;

		size_t counter = 0;		

		// Check if the only instruction is a jump imm to the next basic block
		// Also make sure that the block is only referenced by one previous block
		//
		if (blk->size() == 1 &&			//only one instruction
			blk->next.size() == 1 &&	//only accessed from one path
			blk->prev.size() == 1 &&	//only jumping to one destination				
			blk->back().base->is_branching_virt())
		{
			fassert(blk->front() == blk->back());

			// This should never happen in real world cases. We check for "jmp only", which implies zero changes to the stack
			// This might happen if you write a test case, but shouldn't be possible otherwise
			//
			fassert(blk->sp_offset == 0);

			basic_block* next = blk->next[0];
			basic_block* prev = blk->prev[0];				

			// Remove the block from the next hierarchy
			//	
			for (auto& it : prev->next)
			{
				if (it->entry_vip == blk->entry_vip)
					it = next;
			}

			// Remove the block from the prev hierarchy
			//
			for (auto& it : next->prev)
			{
				if (it->entry_vip == blk->entry_vip)
					it = prev;
			}
			
			fassert(prev->back().base->branch_operands_vip.size() != 0);

			//Regular loop, because we need the operand index for make_mutable
			//
			for (size_t i = 0; i < prev->back().operands.size(); i++)
			{
				if (!prev->back().operands[i].is_immediate())
					continue;

				auto& ins = make_mutable(prev->back());						
				if (ins.operands[i].imm().ival == blk->entry_vip)
				{
					ins.operands[i].imm().ival = next->entry_vip;
				}	
			}

			// TODO: should we do this with another operands loop? We currently only have "js" that qualifies so a simple if does the job for now
			//			
			auto branching_instruction = prev->back();
			if (branching_instruction.base == &ins::js)
			{
				fassert(branching_instruction.operands.size() == 3);

				// This pass should not interfer with blocks that aren't already touched by branch correction / our corrections above
				//
				if (branching_instruction.operands[1].is_immediate() && branching_instruction.operands[2].is_immediate())
				{
					if (branching_instruction.operands[1].imm().ival == branching_instruction.operands[2].imm().ival)
					{
						auto new_vip = branching_instruction.operands[1].imm();

						auto ins = std::prev(prev->end());						

						(+ins)->base = &ins::jmp;
						(+ins)->operands.resize(1);
						(+ins)->operands[0] = { new_vip.ival, arch::bit_count };

						prev->next.resize(1);

						next->prev.erase(std::find(next->prev.begin(), next->prev.end(), prev));
					}
				}
			}			
			
			obsolete_blocks.emplace(blk);
			counter++;
		}

		// Recurse into destinations:
		//
		for ( auto* dst : blk->next )
			counter += pass( dst, true );

		// Remove queued obsolete blocks
		// Use the first_block variable we saved before to detect recursive depth
		//
		auto rtn = blk->owner;
		if (first_block == blk)
		{			
			for (auto it : obsolete_blocks)
				rtn->delete_block(const_cast<vtil::basic_block*>(it));
		}

		return counter;
	}
	size_t bblock_thunk_removal_pass::xpass(routine* rtn)
	{
		// Invoke recursive optimizer starting from entry point.
		//
		visited.reserve( rtn->num_blocks() );
		return pass( rtn->entry_point, true );
	}
};
