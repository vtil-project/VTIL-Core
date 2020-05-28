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
#include "normalize_stack.hpp"
#include <vector>
#include <vtil/query>
#include <vtil/symex>

namespace vtil::optimizer
{
	// This routine tries to pin the stack pointer within the basic block by
	// attempting to eradicate instructons writing into the stack pointer.
	//
	static void pin_stack_pointer( basic_block* block, size_t& counter )
	{
		cached_tracer ctrace = {};

		// => Begin a foward iterating query.
		//
		query::create( block->begin(), +1 )

			// >> Skip volatile instructions.
			.where( [ ] ( instruction& ins ) { return !ins.is_volatile(); } )
			
			// | Filter to instructions that changes stack instances.
			.where( [ ] ( instruction& ins ) { return ins.sp_reset; } )

			// := Project back to iterator type.
			.unproject()

			// @ For each:
			.for_each( [ & ] ( const il_iterator& it )
			{
				// Calculate the difference between current virtual stack pointer 
				// and the next stack pointer instance.
				//
				auto sp_curr = ctrace( { it, REG_SP } ) + it->sp_offset;
				auto sp_next = ctrace( { std::next( it ), REG_SP } );

				// If it simplifies to a constant, replace with a stack shift.
				//
				if ( auto shift_offset = ( sp_next - sp_curr ).get<int64_t>() )
				{
					it->base = &ins::vpinr;
					it->operands = { { REG_SP } };
					block->shift_sp( *shift_offset, true, it );
					ctrace.flush();
					fassert( it->is_valid() );
					counter++;
				}
			} );
	}

	// This routine tries to replace any instruction that reads or writes
	// to a non-sp based pointer into one that references stack with an offset.
	//
	static void simplify_stack_references( basic_block* block, size_t& counter )
	{
		cached_tracer ctrace = {};

		// => Begin a foward iterating query.
		//
		query::create( block->begin(), +1 )

			// >> Skip volatile instructions.
			.where( [ ] ( instruction& ins ) { return !ins.is_volatile(); } )
			
			// | Filter to instructions that operate with non-sp based pointers.
			.where( [ ] ( instruction& ins ) { return ins.base->accesses_memory() && !ins.memory_location().first.is_stack_pointer(); } )

			// := Project back to iterator type.
			.unproject()

			// @ For each:
			.for_each( [ & ] ( const il_iterator& it )
			{
				// Try to simplify pointer to SP + C.
				//
				auto delta = ctrace( { it, it->memory_location().first } ) -
							 ctrace( { it, REG_SP } );

				// If successful, replace the operands.
				//
				if ( auto stack_offset = delta.get<int64_t>() )
				{
					it->operands[ it->base->memory_operand_index ] = { REG_SP };
					it->operands[ it->base->memory_operand_index + 1 ].imm().i64 += *stack_offset;
					fassert( it->is_valid() );
					counter++;
				}
			} );
	}

	// This routine tries to replace as many load instructions it can 
	// with move equivalents in preperation of stack eviction attempt.
	//
	static void propagate_load_from_stack( basic_block* block, size_t& counter )
	{
		// Wrap cached tracer with a filter that returns a constant pseudo-variable for each
		// register query representing $sp and rejects queries of registers.
		//
		struct lazy_tracer : cached_tracer
		{
			symbolic::expression trace( symbolic::variable lookup ) override
			{
				// If register:
				//
				if ( lookup.is_register() )
				{
					// If stack pointer, return unique pseudo-register per stack instance.
					//
					if ( lookup.reg().is_stack_pointer() )
					{
						register_desc desc = {
							register_local,
							lookup.at->sp_index,
							lookup.reg().bit_count
						};
						return symbolic::variable{ lookup.at.container->begin(), desc }.to_expression();
					}

					// Otherwise, return without tracing.
					//
					return lookup.to_expression();
				}

				// Fallback to default tracer.
				//
				return cached_tracer::trace( lookup );
			}
		} tracer = {};

		// => Begin a foward iterating query.
		//
		query::create( block->begin(), +1 )

			// >> Skip volatile instructions.
			.where( [ ] ( instruction& ins ) { return !ins.is_volatile(); } )
			
			// | Filter to LDD instructions referencing stack:
			.where( [ ] ( instruction& ins ) { return *ins.base == ins::ldd && ins.memory_location().first.is_stack_pointer(); } )

			// := Project back to iterator type.
			.unproject()
			
			// @ For each:
			.for_each( [ & ] ( const il_iterator& it )
			{
				auto* new_instruction = &ins::mov;
			
				// Lazy-trace the value.
				//
				symbolic::pointer ptr = { tracer( { it, REG_SP } ) + it->memory_location().second };
				symbolic::expression exp = tracer( { it, { ptr, bitcnt_t( it->access_size() * 8 ) } } );

				// Resize and pack variables.
				//
				exp = symbolic::variable::pack_all( exp.resize( it->operands[ 0 ].size() * 8 ) );

				// If result is an expression:
				//
				if ( exp.is_expression() )
				{
					// If __ucast(V, N):
					//
					if ( exp.op == math::operator_id::ucast && exp.lhs->is_variable() )
					{
						exp = exp.lhs->clone();
					}
					// If __cast(V, N):
					//
					else if ( exp.op == math::operator_id::cast && exp.lhs->is_variable() )
					{
						exp = exp.lhs->clone();
						new_instruction = &ins::movsx;
					}
					// Otherwise skip.
					//
					else
					{
						return;
					}
				}

				// If constant, replace with [mov reg, imm].
				//
				if ( auto imm = exp.get() )
				{
					it->base = new_instruction;
					it->operands = { it->operands[ 0 ], operand{ *imm, exp.size() } };
					fassert( it->is_valid() );
					counter++;
				}
				// Otherwise, try to replace with [mov reg, reg].
				//
				else
				{
					fassert( exp.is_variable() );
					
					// Skip if not a register.
					//
					symbolic::variable& var = exp.uid.get<symbolic::variable>();
					if ( !var.is_register() )
						return;
					register_desc reg = var.reg();
					il_iterator access_point = block->acquire( var.at );

					// Determine if the value is still alive.
					//
					bool is_alive = !reg.is_volatile();
					for ( auto it2 = access_point; !it2.is_end() && is_alive && it2 != it; it2++ )
						is_alive &= !var.written_by( it2, &tracer );

					// If not, try hijacking the value declaration.
					//
					if ( !is_alive )
					{
						// If valid iterator and is of type STR:
						//
						if ( access_point.is_valid() && *access_point->base == ins::str )
						{
							// Insert a move-to-temporary before this instruction 
							// and swap the source operand with the temporary.
							//
							register_desc reg_new = block->tmp( reg.bit_count );
							block->insert( access_point, { &ins::mov, { reg_new, reg } } );
							access_point->operands[ 2 ] = reg_new;

							// Replace source register and declare alive.
							//
							reg = reg_new;
							is_alive = true;
						}
					}

					// Skip if not alive.
					//
					if ( !is_alive )
						return;

					// Replace with a mov.
					//
					it->base = new_instruction;
					it->operands = { it->operands[ 0 ], reg };
					fassert( it->is_valid() );
					++counter;
				}
			});
	}

	// This routine tries to kick as many local variables out of the 
	// stack as possible.
	//
	static void evict_from_stack( basic_block* block, size_t& counter )
	{
		// => Begin a foward iterating query.
		//
		query::create( block->begin(), +1 )

			// >> Skip volatile instructions.
			.where( [ ] ( instruction& ins ) { return !ins.is_volatile(); } )
			
			// | Filter to STR instructions referencing stack:
			.where( [ ] ( instruction& ins ) { return *ins.base == ins::str && ins.memory_location().first.is_stack_pointer(); } )

			// := Project back to iterator type.
			.unproject()
			
			// @ For each:
			.for_each( [ & ] ( const il_iterator& it )
			{
				// Create a mask for the value.
				//
				uint64_t mask = math::fill( it->access_size() * 8 );
				int64_t offset = it->memory_location().second;

				// For each instruction afterwards within the same stack instance until mask is reset.
				//
				for ( auto it2 = std::next( it ); !it2.is_end() && mask && it2->sp_index == it->sp_index; it2++ )
				{
					// If instruction does access stack:
					//
					if ( it2->base->accesses_memory() &&
						 it2->memory_location().first.is_stack_pointer() )
					{
						// Determine the mask of the relative access.
						//
						uint64_t mask_access = math::fill(
							it2->access_size() * 8,
							offset - it2->memory_location().second
						);

						// If instruction reads from memory:
						//
						if ( it2->base->reads_memory() )
						{
							// Stored variable is being used, fail.
							//
							if ( mask & mask_access )
							{
								// TODO: Do we need to try propagating?
								//
								break;
							}
						}
						// If instruction writes to memory:
						//
						else if ( it2->base->writes_memory() )
						{
							// Reset overwritten bits.
							//
							mask &= ~mask_access;
						}
					}
				}

				// If not dead, fail.
				//
				if ( mask )
					return;

				// Replace with a NOP.
				//
				it->base = &ins::nop;
				it->operands = {};
				++counter;
			});
	}
	
	// Attempts to reduce the number of different stack instances used,
	// resolves load and store operations using non-sp pointers into
	// SP+C where possible and converts local variables in virtual
	// stack into explicit temporaries if applicable.
	//
	size_t stack_normalization_pass::pass( basic_block* blk, bool xblock )
	{
		// Apply each routine.
		//
		size_t counter = 0;
		pin_stack_pointer( blk, counter );
		simplify_stack_references( blk, counter );
		propagate_load_from_stack( blk, counter );
		evict_from_stack( blk, counter );

		// Clean up the instruction stream.
		//
		blk->stream.remove_if( [ ] ( instruction& ins )
		{
			return !ins.explicit_volatile && *ins.base == ins::nop;
		} );

		return counter;
	}
};
