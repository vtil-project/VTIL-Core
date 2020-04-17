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

	// Helpers for the allocation of unique temporary registers
	//
	arch::register_view basic_block::tmp( uint8_t size )
	{
		return arch::register_view
		{
			"t" + std::to_string( ++owner->temporary_index_counter ),
			0,
			size
		};
	}

	// Instruction pre-processor
	//
	void basic_block::append_instruction( instruction ins )
	{
		// Cannot access EFLAGS directly.
		//
		static const auto EFLAGS_MAPPINGS = { std::pair{ REG_OF, X86_EFLAGS_OF_BIT },
			std::pair{ REG_SF, X86_EFLAGS_SF_BIT },
			std::pair{ REG_ZF, X86_EFLAGS_ZF_BIT },
			std::pair{ REG_AF, X86_EFLAGS_AF_BIT },
			std::pair{ REG_PF, X86_EFLAGS_PF_BIT } };

		if ( int w_op = ins.writes_to( X86_REG_EFLAGS ) )
		{
			auto t1 = tmp( 8 );
			mov( t1, 0ull );
			ins.operands[ w_op - 1 ].reg.base = t1.base;

			append_instruction( ins );

			for ( auto& pair : EFLAGS_MAPPINGS )
			{
				auto t0 = tmp( 8 );
				mov( t0, t1 );
				bshr( t0, pair.second );
				band( t0, 1 );
				mov( pair.first, t0 )->stream.back().make_volatile();
			}
			return;
		}
		if ( int r_op = ins.reads_from( X86_REG_EFLAGS ) )
		{
			auto t1 = tmp( 8 );
			mov( t1, 0ull );
			ins.operands[ r_op - 1 ].reg.base = t1.base;

			for ( auto& pair : EFLAGS_MAPPINGS )
			{
				auto t0 = tmp( 8 );
				mov( t0, pair.first );
				bshl( t0, pair.second );
				band( t0, 1ull << pair.second );
				bor( t1, t0 );
			}
		}

		fassert( !ins.writes_to( X86_REG_EFLAGS ) && !ins.reads_from( X86_REG_EFLAGS ) );

		// Instructions cannot be appended after a branching instruction was hit.
		//
		fassert( !is_complete() );

		// Write the stack pointer details.
		//
		ins.sp_offset = sp_offset;
		ins.sp_index = sp_index;

		// If instruction writes to RSP, reset the queued stack pointer.
		//
		if ( ins.writes_to( X86_REG_RSP ) )
		{
			sp_offset = 0;
			sp_index++;
			ins.sp_reset = true;
		}

		// Append the instruction to the stream.
		//
		stream.push_back( ins );
	}

	// Updates EFLAGS register based on the previous instruction executed and writes it
	// into the operand given.
	//
	basic_block* basic_block::uflags_result( operand op, bool carry )
	{
		// SF, ZF, PF will be set according to the result.
		//
		//
		// AF will be set to undefined, as they are not implemented yet.
		// OF, CF will be cleared.

		this->setz( REG_ZF, op )
			->sets( REG_SF, op )
			->setp( REG_PF, op )
			->mov( REG_AF, REG_UNKB );
		if ( carry )
			seto( REG_OF, op )->setc( REG_CF, op );
		else
			mov( REG_OF, 0ull )->mov( REG_CF, 0ull );
		return this;
	}

	// Queues a stack shift.
	//
	basic_block* basic_block::shift_sp( int64_t offset, bool merge_instance, iterator it )
	{
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
		std::optional<uint32_t> sp_index_prev;
		while ( !it.is_end() )
		{
			// Shift the stack offset accordingly.
			//
			it->sp_offset += offset;

			// If instruction reads from RSP:
			//
			if ( it->reads_from( X86_REG_RSP ) )
			{
				// If LDR|STR with memory operand RSP:
				//
				if ( it->base->accesses_memory() && it->operands[ it->base->memory_operand_index ].reg == X86_REG_RSP )
				{
					// Assert the offset operand is an immediate and 
					// shift the offset as well.
					//
					fassert( it->operands[ it->base->memory_operand_index + 1 ].is_immediate() );
					it->operands[ it->base->memory_operand_index + 1 ].i64 += offset;
				}
			}

			// If stack changed changed, return, else forward the iterator.
			//
			if ( sp_index_prev.value_or( it->sp_index ) != it->sp_index )
				return this;
			sp_index_prev = it->sp_index;
			++it;
		}

		// Shift the stack pointer and continue as usual
		// without emitting any sub or add instructions.
		// Queued stack pointer changes will be processed
		// in bulk at the end of the routine.
		//
		sp_offset += offset;
		return this;
	}

	// Pushes current flags value up the stack queueing the
	// shift in stack pointer.
	//
	basic_block* basic_block::pushf()
	{
		return push( X86_REG_EFLAGS );
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
};