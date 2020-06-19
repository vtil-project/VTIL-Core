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
#include "basic_block.hpp"
#include <vtil/amd64> // TODO: Remove me

namespace vtil
{
	// Constructor does not exist. Should be created either using
	// ::begin(...) or ->fork(...).
	//
	basic_block* basic_block::begin( vip_t entry_vip )
	{
		// Caller must provide a valid virtual instruction pointer.
		//
		fassert( entry_vip != invalid_vip );

		// Create the basic block with depth = 0, identifier = "0"
		//
		basic_block* blk = new basic_block;
		blk->entry_vip = entry_vip;

		// Create the routine and assign this block as the entry-point
		//
		blk->owner = new routine;
		blk->owner->entry_point = blk;
		blk->owner->explored_blocks[ entry_vip ] = blk;

		// Return the block
		//
		return blk;
	}
	basic_block* basic_block::fork( vip_t entry_vip )
	{

		// Block cannot be forked before a branching instruction is hit.
		//
		fassert( is_complete() );

		// Caller must provide a valid virtual instruction pointer.
		//
		fassert( entry_vip != invalid_vip );

		// Check if the routine has already explored this block.
		//
		std::lock_guard g( owner->mutex );
		basic_block* result = nullptr;
		basic_block*& entry = owner->explored_blocks[ entry_vip ];
		if ( !entry )
		{
			// If it did not, create a block and assign it.
			//
			result = new basic_block;
			result->owner = owner;
			result->entry_vip = entry_vip;
			result->sp_offset = 0;
			entry = result;
		}

		// Fix the links and quit the scope holding the lock.
		//
		next.push_back( entry );
		entry->prev.push_back( this );
		return result;
	}

	// Labels are a simple way to assign the same VIP for multiple 
	// instructions that will be pushed after the call.
	//
	basic_block* basic_block::label_begin( vip_t vip )
	{
		label_stack.push_back( vip );
		return this;
	}
	basic_block* basic_block::label_end()
	{
		label_stack.pop_back();
		return this;
	}

	// Drops const qualifier from iterator after asserting iterator
	// belongs to this basic block.
	//
	basic_block::iterator basic_block::acquire( const const_iterator& it )
	{
		// If invalid return as is.
		//
		if ( !it.is_valid() ) return {};
		
		// This is only valid for iterators belonging to current container.
		//
		fassert( this == it.container );

		// If end return end.
		//
		if ( it.is_end() ) return end();

		// Cast away the qualifier using erase and create a non-const qualified iterator.
		//
		return { this, this->stream.erase( it, it ) };
	}

	// Wrap std::list::erase.
	//
	basic_block::iterator basic_block::erase( const const_iterator& it )
	{
		return { this, stream.erase( it ) };
	}

	// Wrap std::list::insert with stack state-keeping.
	//
	basic_block::iterator basic_block::insert( const const_iterator& it_const, instruction&& ins )
	{
		fassert( ins.is_valid() );

		// If label stack is not empty and instruction has an invalid vip, use the last label pushed.
		//
		if ( !label_stack.empty() && ins.vip == invalid_vip )
			ins.vip = label_stack.back();

		// Drop const qualifier of the iterator, since we are in a non-const 
		// qualified member function, this qualifier is unnecessary.
		//
		iterator it = it_const.is_end() ? end() : acquire( it_const );

		// Instructions cannot be appended after a branching instruction was hit.
		//
		if ( it.is_end() && !it.is_begin() )
			fassert( !std::prev( it )->base->is_branching() );

		// If inserting at end, inherit stack properties from the container.
		//
		if ( it.is_end() )
		{
			ins.sp_offset = sp_offset;
			ins.sp_index = sp_index;
		}
		// If inserting at the beginning, assume clean stack state.
		//
		else if ( it.is_begin() )
		{
			ins.sp_offset = 0;
			ins.sp_index = 0;
		}
		// If inserting in the middle of the stream:
		//
		else
		{
			auto prev = std::prev( it );

			// If previous instruction resets stack, use clean state of next index.
			//
			if ( prev->sp_reset )
			{
				ins.sp_index = prev->sp_index + 1;
				ins.sp_offset = 0;
			}
			// Otherwise inherit the state as is.
			//
			else
			{
				ins.sp_index = prev->sp_index;
				ins.sp_offset = prev->sp_offset;
			}
		}

		// If instruction writes to SP, reset the queued stack pointer.
		//
		for ( auto [op, type] : ins.enum_operands() )
		{
			if ( type >= operand_type::write && op.reg().is_stack_pointer() )
			{
				shift_sp( -ins.sp_offset, false, it );
				for ( auto it2 = it; !it2.is_end(); it2++ )
					it2->sp_index++;
				sp_index++;
				ins.sp_reset = true;
				break;
			}
		}

		// Append the instruction to the stream.
		//
		return { this, stream.emplace( it, std::move( ins ) ) };
	}

	// Queues a stack shift.
	//
	basic_block* basic_block::shift_sp( int64_t offset, bool merge_instance, const const_iterator& it_const )
	{
		// Drop const qualifier of the iterator, since we are in a non-const 
		// qualified member function, this qualifier is unnecessary.
		//
		iterator it = acquire( it_const );

		// If requested, shift the stack index first.
		//
		if ( merge_instance )
		{
			// Assert instruction at iterator indeed resets stack pointer.
			//
			fassert( !it.is_end() && it->sp_reset );

			// Decrement stack index for each instruction afterwards.
			//
			for ( auto i = std::next( it ); !i.is_end(); i++ )
				i->sp_index--;
			sp_index--;

			// Remove the reset flag and merge the offsets.
			//
			it->sp_reset = false;
			offset += it->sp_offset;
			it->sp_offset = 0;
		}

		// If an iterator is provided, shift the stack pointer
		// for every instruction that precedes it as well.
		//
		uint32_t shifted_spi = it.is_end() ? -1 : it->sp_index;
		for ( ;!it.is_end() && it->sp_index == shifted_spi; it++ )
		{
			// Shift the stack offset accordingly.
			//
			it->sp_offset += offset;

			// If memory operation:
			//
			if ( it->base->accesses_memory() )
			{
				// If base is stack pointer, add the offset.
				//
				auto [base, off] = it->memory_location();
				if ( base.is_stack_pointer() )
					off += offset;
			}
		}

		// If we've reached the end, shift the final block offset as well.
		//
		if( it.is_end() ) sp_offset += offset;
		return this;
	}

	// Emits an entire instruction using series of VEMITs.
	//
	basic_block* basic_block::vemits( const std::string& assembly )
	{
		auto res = keystone::assemble( assembly );
		fassert( !res.empty() );
		for ( uint8_t byte : res )
			vemit( byte );
		return this;
	}

	// Generates a hash for the block.
	//
	hash_t basic_block::hash() const
	{
		return make_hash( entry_vip, sp_offset, sp_index, last_temporary_index, stream );
	}
};