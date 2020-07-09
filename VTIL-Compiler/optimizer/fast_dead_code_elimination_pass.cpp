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
#include "fast_dead_code_elimination_pass.hpp"
#include <vtil/query>
#include <vtil/utility>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Returns whether the instruction is a semantic equivalent of NOP or not.
	//
	static bool is_semantic_nop( const instruction &ins )
	{
		if ( *ins.base == ins::nop )
			return true;

		if ( *ins.base == ins::mov || *ins.base == ins::movsx )
		{
			if ( ins.operands[0] == ins.operands[1] )
				return true;
		}

		return false;
	}

	size_t fast_dead_code_elimination_pass::fast_xblock_dce( basic_block* blk )
	{
		// If we've already been sealed, return.
		//
		if ( auto it = sealed.find( blk ); it != sealed.end() )
			return 0;

		size_t counter = 0;

		// Mask off register reads in this block immediately, to ensure validity of successors.
		//
		auto& reg_read_masks = reg_map[ blk ];
		for ( auto it = blk->begin(); !it.is_end(); it++ )
		{
			auto& ins = *it;
			// For every read in this instruction...
			//
			for ( auto[op, type] : ins.enum_operands())
			{
				// If not a global register, continue.
				//
				if ( !op.is_register() || !op.reg().is_global() )
					continue;

				// If we're reading from a non-local register, mark mask.
				//
				if ( type != operand_type::write && type != operand_type::invalid )
					reg_read_masks[register_id( op.reg())] |= op.reg().get_mask();
			}
		}

		// Seal us.
		//
		sealed.emplace( blk );

		for ( auto* next : blk->next )
		{
			// If we have any non-sealed successors, run on them first.
			//
			if ( auto it = sealed.find( next ); it == sealed.end() )
				counter += fast_xblock_dce( next );

			// Update read mask.
			//
			for ( auto& [ reg_id, mask ] : reg_map[ next ] )
				reg_read_masks[ reg_id ] |= mask;
		}

		auto[rbegin, rend] = reverse_iterators( *blk );
		for ( auto it = rbegin; it != rend; )
		{
			// Increment iterator.
			const auto last_iter = it;
			++it;

			// Grab instruction.
			//
			auto &ins = *last_iter;

			auto removed = false;

			// If volatile, continue.
			//
			if ( !ins.is_volatile())
			{
				// For every operand in this instruction...
				//
				for ( auto[op, type] : ins.enum_operands())
				{
					// If not a register, continue.
					//
					if ( !op.is_register() )
						continue;

					// If we're writing to this register, check previous writes and remove dead ones. Break immediately because there's only one written register per instruction.
					//
					if ( type >= operand_type::write )
					{
						const auto reg_id = register_id( op.reg());
						const auto write_mask = op.reg().get_mask();

						// Grab current read mask or zero.
						//
						if ( auto read_iter = reg_read_masks.find( reg_id ); read_iter != reg_read_masks.end())
						{
							auto& read_mask = read_iter->second;

							// If read mask does not overlap write mask, this instruction is dead.
							//
							if (( read_mask & write_mask ) == 0 )
							{
								// If we don't have a read mask, we can remove this instruction.
								//
								++counter;
								removed = true;
								blk->erase( last_iter );
								break;
							}

							// Update read mask.
							//
							read_mask &= ~write_mask;
						}
						else
						{
							// Update read mask.
							//
							reg_read_masks.emplace( reg_id, ~0ULL & ~write_mask );
						}

						// Break out as we've found a write, and instructions contain only one.
						//
						break;
					}
				}
			}

			// Make sure we're not checking an invalid memory location.
			//
			if (removed)
				continue;

			// For every read in this instruction...
			//
			for ( auto[op, type] : ins.enum_operands())
			{
				// If not a register, continue.
				//
				if ( !op.is_register() )
					continue;

				// If we're reading from a register, mark mask.
				//
				if ( type != operand_type::write && type != operand_type::invalid )
					reg_read_masks[register_id( op.reg())] |= op.reg().get_mask();
			}
		}

		return counter;
	}

	// Implement the pass.
	//
	size_t fast_local_dead_code_elimination_pass::pass( basic_block *blk, bool xblock )
	{
		size_t counter = 0;

		if ( blk->stream.empty())
			return 0;

		// Remove all semantic nop.
		//
		for ( auto it = blk->begin(); it != blk->end(); )
		{
			if ( !it->is_volatile() && is_semantic_nop( *it ))
			{
				auto it_cpy = it;
				++it;
				++counter;
				blk->erase( it_cpy );
			}
			else
				++it;
		}

		// First pass: remove trivially redundant register writes and memory accesses.
		// 1. Iterate backwards through the basic block.
		// 2. Cache the last relevant writes through a vector to the write mask and the instruction that wrote them.
		// 3. When a write is fully overwritten, check whether there was a read overlapping that write. If not, the write is dead.
		//
		std::unordered_map< register_id, uint64_t > reg_read_masks;

		// Assume written physical registers and all memory operands set are live at the end of the block.
		//
		for ( auto it = blk->begin(), it_e = blk->end(); it != it_e; ++it )
		{
			// Grab instruction.
			//
			auto &ins = *it;

			// For every write, mark physical registers as live.
			for ( auto[op, type] : ins.enum_operands())
			{
				// If not a register, continue.
				//
				if ( !op.is_register())
					continue;

				const auto reg = op.reg();

				// If a temporary, continue.
				//
				if ( reg.is_local() )
					continue;

				// Mark register as read.
				//
				if ( type >= operand_type::write )
				{
					reg_read_masks[register_id( reg )] = ~0ULL;
					break;
				}
			}
		}

		auto[rbegin, rend] = reverse_iterators( *blk );
		for ( auto it = rbegin; it != rend; )
		{
			// Increment iterator.
			const auto last_iter = it;
			++it;

			// Grab instruction.
			//
			auto &ins = *last_iter;

			auto removed = false;

			// If volatile, continue to read access.
			//
			if ( !ins.is_volatile())
			{
				// For every operand in this instruction...
				//
				for ( auto[op, type] : ins.enum_operands())
				{
					// If not a register, continue.
					//
					if ( !op.is_register())
						continue;

					// If we're writing to this register, check previous writes and remove dead ones. Break immediately because there's only one written register per instruction.
					//
					if ( type >= operand_type::write )
					{
						const auto reg_id = register_id( op.reg());
						const auto write_mask = op.reg().get_mask();

						// Grab current read mask or zero.
						//
						uint64_t read_mask = 0;
						if ( auto read_iter = reg_read_masks.find( reg_id ); read_iter != reg_read_masks.end())
							read_mask = read_iter->second;

						// If read mask does not overlap write mask, this instruction is dead.
						//
						if (( read_mask & write_mask ) == 0 )
						{
							// If we don't have a read mask, we can remove this instruction.
							//
							++counter;
							blk->erase( last_iter );
							removed = true;
							break;
						}

						// Update read mask.
						//
						reg_read_masks[reg_id] &= ~write_mask;

						// Break out as we've found a write, and instructions contain only one.
						//
						break;
					}
				}
			}

			if (removed)
				continue;

			// For every read in this instruction...
			//
			for ( auto[op, type] : ins.enum_operands())
			{
				// If not a register, continue.
				//
				if ( !op.is_register())
					continue;

				// If we're reading from this register, mark mask.
				//
				if ( type != operand_type::write && type != operand_type::invalid )
					reg_read_masks[register_id( op.reg())] |= op.reg().get_mask();
			}
		}

		// Purge simplifier cache since block iterators are invalided thus cache may fail.
		//
		if ( counter != 0 )
			symbolic::purge_simplifier_cache();

		return counter;
	}
}