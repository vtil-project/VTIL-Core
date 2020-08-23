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
#include <numeric>
#include "stack_pinning_pass.hpp"
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t stack_pinning_pass::pass( basic_block* blk, bool xblock )
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

			// Filter to instructions that changes stack instances.
			//
			if ( it->sp_reset )
			{
				// Calculate the difference between current virtual stack pointer 
				// and the next stack pointer instance.
				//
				auto sp_curr = ctrace( { it, REG_SP } ) + it->sp_offset;
				auto sp_next = ctrace( { std::next( it ), REG_SP } );

				// If it simplifies to a constant:
				//
				if ( auto shift_offset = ( sp_next - sp_curr ).get<int64_t>() )
				{
					// Replace with a stack shift.
					//
					( +it )->base = &ins::nop;
					( +it )->operands = {};
					blk->shift_sp( *shift_offset, true, it );

					// Flush tracer cache.
					//
					ctrace.flush();

					// Validate modification and increment counter.
					//
					it->is_valid( true );
					counter++;
				}
			}
		}

		// Remove nops.
		//
		aux::remove_nops( blk );

		// If block is complete:
		//
		if ( blk->is_complete() )
		{
			// Iterate each instruction in reverse:
			//
			int64_t sp_offset = blk->sp_offset;
			auto [bgn, end] = reverse_iterators( *blk );
			for ( auto it = bgn; it != end; ++it )
			{
				// Determine if instruction accesses $sp.
				//
				static const auto indices = [ ] ()
				{
					std::array<size_t, VTIL_ARCH_MAX_OPERAND_COUNT> arr;
					std::iota( arr.begin(), arr.end(), 0 );
					return arr;
				}();

				stack_vector<size_t> read_sp;
				stack_vector<size_t> write_sp;
				for ( auto [op, type, idx] : zip( it->operands, it->base->operand_types, iindices ) )
				{
					// Skip if memory location since it's virtual $sp in that case.
					//
					if ( idx == it->base->memory_operand_index )
						continue;

					// If operand is stack pointer:
					//
					if ( op.is_register() && op.reg().is_stack_pointer() )
					{
						// Add to each list.
						//
						if ( type >= operand_type::write )
						{
							write_sp.push_back( idx );
						}
						else
						{
							if( it->sp_offset != sp_offset )
								read_sp.push_back( idx );
						}
					}
				}

				// If instruction does not write into $sp:
				//
				if ( !write_sp.size() )
				{
					// If instruction reads from $sp:
					//
					if ( read_sp.size() )
					{
						// If volatile, fail and set new target $sp.
						//
						if ( it->is_volatile() )
						{
							sp_offset = it->sp_offset;
							continue;
						}

						// Mov to temporary and substract the target offset.
						//
						auto tmp = blk->tmp( 64 );
						auto mov = blk->insert( it, { &ins::mov, { tmp, REG_SP } } );
						auto sub = blk->insert( it, { &ins::sub, { tmp, make_imm<int64_t>( sp_offset - it->sp_offset ) } } );
						( +mov )->sp_offset = sp_offset;
						( +sub )->sp_offset = sp_offset;
						( +it )->sp_offset = sp_offset;

						// Replace every read.
						//
						for ( size_t index : read_sp )
						{
							( +it )->operands[ index ].reg().combined_id = tmp.combined_id;
							( +it )->operands[ index ].reg().flags = tmp.flags;
						}
						
						// Continue iteration.
						//
						it = { mov, blk->begin() };
						counter++;
						continue;
					}

					// Replace stack pointer offset and continue.
					//
					if ( it->sp_offset != sp_offset )
						( +it )->sp_offset = sp_offset, counter++;
				}
				else
				{
					// Set new target $sp and continue.
					//
					sp_offset = it->sp_offset;
				}
			}
		}
		return counter;
	}
};