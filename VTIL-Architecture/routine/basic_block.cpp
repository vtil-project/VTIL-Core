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
#include "basic_block.hpp"
#include <vtil/amd64>
#include <vtil/arm64>

namespace vtil
{
	// Creates a new block bound to a new routine with the given parameters.
	//
	basic_block* basic_block::begin( vip_t entry_vip, architecture_identifier arch_id )
	{
		// Caller must provide a valid virtual instruction pointer.
		//
		fassert( entry_vip != invalid_vip );

		// Create a routine and invoke create block.
		//
		routine* rtn = new routine{ arch_id };
		return rtn->create_block( entry_vip ).first;
	}

	// Creates a new block connected to this block at the given vip, if already explored returns nullptr,
	// should still be called if the caller knowns it is explored since this function creates the linkage.
	//
	basic_block* basic_block::fork( vip_t entry_vip )
	{
		// Block cannot be forked before a branching instruction is hit.
		//
		fassert( is_complete() );

		// Caller must provide a valid virtual instruction pointer.
		//
		fassert( entry_vip != invalid_vip );

		// Invoke create block.
		//
		auto [blk, inserted] = owner->create_block( entry_vip, this );
		return inserted ? blk : nullptr;
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
				( +i )->sp_index--;
			sp_index--;

			// Remove the reset flag and merge the offsets.
			//
			( +it )->sp_reset = false;
			offset += it->sp_offset;
			( +it )->sp_offset = 0;
		}

		// If an iterator is provided, shift the stack pointer
		// for every instruction that precedes it as well.
		//
		uint32_t shifted_spi = it.is_end() ? -1 : it->sp_index;
		for ( ;!it.is_end() && it->sp_index == shifted_spi; it++ )
		{
			// Shift the stack offset accordingly.
			//
			( +it )->sp_offset += offset;

			// If memory operation:
			//
			if ( it->base->accesses_memory() )
			{
				// If base is stack pointer, add the offset.
				//
				auto [base, off] = ( +it )->memory_location();
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
		std::vector<uint8_t> bytes;

		switch ( owner->arch_id )
		{
			case architecture_amd64: bytes = amd64::assemble( assembly ); break;
			case architecture_arm64: bytes = arm64::assemble( assembly ); break;
			default: unreachable();
		}

		fassert( !bytes.empty() );
		for ( uint8_t byte : bytes )
			vemit( byte );
		return this;
	}

	// Pushes an operand up the stack queueing the
	// shift in stack pointer.
	//
	basic_block* basic_block::push( const operand& op )
	{
		// Handle SP specially since we change the stack pointer
		// before the instruction begins.
		//
		if ( op.is_register() && op.reg().is_stack_pointer() )
		{
			auto t0 = tmp( 64 );
			return mov( t0, op )->push( t0 );
		}

		// If operand size is not aligned:
		//
		if ( size_t misalignment = op.size() % VTIL_ARCH_POPPUSH_ENFORCED_STACK_ALIGN )
		{
			// Adjust for misalignment and zero the padding.
			//
			int64_t padding_size = VTIL_ARCH_POPPUSH_ENFORCED_STACK_ALIGN - misalignment;
			shift_sp( -padding_size );
			str( REG_SP, sp_offset, operand( 0, math::narrow_cast<bitcnt_t>( padding_size * 8 ) ) );
		}

		// Shift and write the operand.
		//
		shift_sp( -int64_t( op.size() ) );
		str( REG_SP, sp_offset, op );
		return this;
	}

	// Pops an operand from the stack queueing the
	// shift in stack pointer.
	//
	basic_block* basic_block::pop( const operand& op )
	{
		// Save the pre-shift offset.
		//
		int64_t offset = sp_offset;

		// If operand size is not aligned:
		//
		if ( size_t misalignment = op.size() % VTIL_ARCH_POPPUSH_ENFORCED_STACK_ALIGN )
		{
			// Adjust for misalignment.
			//
			shift_sp( VTIL_ARCH_POPPUSH_ENFORCED_STACK_ALIGN - misalignment );
		}

		// Shift and read to the operand.
		//
		shift_sp( op.size() );
		ldd( op, REG_SP, offset );
		return this;
	}

	// Instruction deletion.
	//
	il_iterator basic_block::erase( const const_iterator& pos )
	{
		// Increment epoch to signal modification.
		//
		epoch++;

		// If no previous entry, head and possibly also tail:
		//
		list_entry* entry = pos.entry;
		if ( !entry->prev )
		{
			// Set head, if valid fix prev link, otherwise fix tail.
			//
			if ( head = entry->next )
				head->prev = nullptr;
			else
				tail = nullptr;
		}
		// If there is previous, but no next, tail:
		//
		else if ( !entry->next )
		{
			// Set new tail and fix next link.
			//
			tail = entry->prev;
			tail->next = nullptr;
		}
		// Else generic entry, fix links:
		//
		else
		{
			entry->prev->next = entry->next;
			entry->next->prev = entry->prev;
		}

		// Delete the entry and return next.
		//
		iterator npos = { this, entry->next };
		destruct_instruction( entry );
		instruction_count--;
		return npos;
	}
	basic_block* basic_block::clear()
	{
		// Destruct every entry.
		//
		for ( auto it = head; it; )
		{
			auto next = it->next;
			destruct_instruction( it );
			it = next;
		}

		// Reset the state saved and return self.
		//
		head = nullptr;
		tail = nullptr;
		epoch++;
		instruction_count = 0;
		return this;
	}
	instruction basic_block::pop_front()
	{
		// Save instruction at head and erase it.
		//
		dassert( head );
		instruction result = std::move( head->value );
		erase( { this, head } );
		return result;
	}
	instruction basic_block::pop_back()
	{
		// Save instruction at tail and erase it.
		//
		dassert( tail );
		instruction result = std::move( tail->value );
		erase( { this, tail } );
		return result;
	}

	// Internally invoked by emplace to insert a new linked list entry to the instruction stream.
	//
	il_iterator basic_block::insert_final( const const_iterator& pos, list_entry* new_entry, bool process )
	{
		// Increment epoch to signal modification.
		//
		epoch++;

		// If marked to be processed:
		//
		if( process )
		{
			// Validate instruction.
			//
			auto& ins = new_entry->value;
			ins.is_valid( true );

			// Validate registers are of matching architecture.
			//
			for ( auto& op : ins.operands )
			{
				if ( op.is_register() && op.reg().is_physical() && !op.reg().is_special() )
					fassert( op.reg().architecture == owner->arch_id );
			}

			// If label stack is not empty and instruction has an invalid vip, use the last label pushed.
			//
			if ( !label_stack.empty() && ins.vip == invalid_vip )
				ins.vip = label_stack.back();

			// Instructions cannot be appended after a branching instruction was hit.
			//
			auto& it = acquire( pos );
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
				// If previous instruction resets stack, use clean state of next index.
				//
				auto prev = std::prev( it );
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
						( +it2 )->sp_index++;
					sp_index++;
					ins.sp_reset = true;
					break;
				}
			}
		}

		// If iterator has a valid entry:
		//
		if ( pos.entry )
		{
			// Link before it.
			//
			new_entry->prev = pos.entry->prev;
			new_entry->next = pos.entry;
			pos.entry->prev = new_entry;

			// Set head/tail if first entry, else fix links.
			//
			if ( new_entry->prev ) new_entry->prev->next = new_entry;
			else                   head = new_entry;
		}
		// Otherwise, only entry or end.
		//
		else
		{
			// Link at the end, set tail.
			//
			new_entry->prev = tail;
			new_entry->next = nullptr;
			tail = new_entry;

			// Set head if first entry, else fix links.
			//
			if ( new_entry->prev ) new_entry->prev->next = new_entry;
			else                   head = new_entry;
		}

		// Increment entry count and return new iterator.
		//
		instruction_count++;
		return { this, new_entry };
	}
};
