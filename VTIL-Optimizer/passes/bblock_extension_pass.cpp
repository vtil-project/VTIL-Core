#include "bblock_extension_pass.hpp"
#include <vtil/query>

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t bblock_extension_pass::pass( basic_block* blk, bool xblock )
	{
		// Skip if local optimization or if already visited.
		//
		if ( !xblock || visit_list.contains( blk ) )
			return 0;

		// While we can form an extended basic block:
		//
		size_t counter = 0;
		while ( blk->next.size() == 1 &&
				blk->next[ 0 ]->prev.size() == 1 &&
				blk->stream.back().base->is_branching_virt() )
		{
			// Pop the branching instruction.
			//
			blk->stream.pop_back();

			// For each instruction in the destination:
			//
			basic_block* blk_next = blk->next[ 0 ];
			for ( instruction& ins : *blk_next )
			{
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
				blk->stream.push_back( std::move( ins ) );
			}

			// Acquire the routine lock.
			//
			std::lock_guard _g( blk->owner->mutex );

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
			blk->owner->explored_blocks.erase( blk_next->entry_vip );
			delete blk_next;
			counter++;
		}

		// Recurse into destinations:
		//
		visit_list.insert( blk );
		for ( auto* dst : blk->next )
			counter += pass( dst, true );
		return counter;
	}
	size_t bblock_extension_pass::xpass( routine* rtn )
	{
		// Clear visit list and invoke recursive extender.
		//
		visit_list = {};
		return pass( rtn->entry_point, true );
	}
};
