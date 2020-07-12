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
#include "stack_propagation_pass.hpp"
#include <vtil/query>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Wrap cached tracer with a filter rejecting queries of registers and specializing recursive tracer.
	//
	struct lazy_tracer : cached_tracer
	{
		bool bypass = false;

		symbolic::expression trace( const symbolic::variable& lookup ) override
		{
			if( bypass || lookup.at.is_end() )
				return cached_tracer::trace( lookup );

			// If iterator is at a str instruction and we're 
			// looking up the stored operand, return without tracing.
			//
			if ( !lookup.at.is_end() && lookup.at->base == &ins::str &&
				 lookup.is_register() && lookup.at->operands[ 2 ].is_register() &&
				 lookup.reg() == lookup.at->operands[ 2 ].reg() &&
				 !lookup.reg().is_stack_pointer() )
			{
				return lookup.to_expression();
			}

			// Fallback to default tracer.
			//
			bypass = true;
			auto result = cached_tracer::trace( lookup );
			bypass = false;
			return result;
		}

		symbolic::expression rtrace( const symbolic::variable& lookup, int64_t limit = -1 ) override
		{
			// Invoke default tracer and store the result.
			//
			bool recursive_flag_prev = recursive_flag;
			recursive_flag = true;
			symbolic::expression result = cached_tracer::trace( lookup );
			recursive_flag = recursive_flag_prev;
			
			// If result is a variable:
			//
			if ( result.is_variable() )
			{
				// If result is a non-local memory variable, invoke rtrace primitive.
				//
				auto& var = result.uid.get<symbolic::variable>();
				if ( var.is_memory() && !aux::is_local( *var.mem().decay() ) )
					return cached_tracer::rtrace( var, limit );
			}
			return result;
		}
	};

	// Implement the pass.
	//
	size_t stack_propagation_pass::pass( basic_block* blk, bool xblock )
	{
		// Acquire a shared lock.
		//
		cnd_shared_lock lock( mtx, xblock );

		// Create tracers.
		//
		lazy_tracer ltracer = {};
		cached_tracer ctracer = {};

		// Allocate the swap buffers.
		//
		std::vector<std::tuple<il_iterator, const instruction_desc*, operand>> ins_swap_buffer;
		std::vector<std::tuple<il_iterator, const instruction_desc*, symbolic::variable>> ins_revive_swap_buffer;

		// => Begin a foward iterating query.
		//
		query::create( blk->begin(), +1 )

			// >> Skip volatile instructions.
			.where( [ ] ( instruction& ins ) { return !ins.is_volatile(); } )
		
			// | Filter to LDD instructions referencing stack:
			.where( [ ] ( instruction& ins ) { return ins.base == &ins::ldd && ins.memory_location().first.is_stack_pointer(); } )

			// := Project back to iterator type.
			.unproject()
		
			// @ For each:
			.for_each( [ & ] ( const il_iterator& it )
			{
				auto resize_and_pack = [ & ] ( symbolic::expression::reference& exp )
				{
					exp = symbolic::variable::pack_all( exp.resize( it->operands[ 0 ].bit_count() ) );
				};

				// Lazy-trace the value.
				//
				symbolic::pointer ptr = { ltracer.cached_tracer::trace_p( { it, REG_SP } ) + it->memory_location().second };
				symbolic::variable var = { it, { ptr, it->access_size() } };
				var.at.paths_allowed = &it.container->owner->get_path( it.container->owner->entry_point, it.container );
				var.at.is_path_restricted = true;
				symbolic::expression::reference exp = xblock ? ltracer.rtrace( var ) : ltracer.cached_tracer::trace( var );

				// Resize and pack variables.
				//
				resize_and_pack( exp );

				// Determine the instruction we will use to move the source.
				//
				auto* new_instruction = &ins::mov;
				if ( exp->is_expression() )
				{
					// If __ucast(V, N):
					//
					if ( exp->op == math::operator_id::ucast && exp->lhs->is_variable() )
					{
						exp = exp->lhs;
					}
					// If __cast(V, N):
					//
					else if ( exp->op == math::operator_id::cast && exp->lhs->is_variable() )
					{
						exp = exp->lhs;
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
				if ( auto imm = exp->get() )
				{
					// Push to swap buffer.
					//
					ins_swap_buffer.emplace_back( it, new_instruction, operand{ *imm, exp->size() } );
				}
				// Otherwise, try to replace with [mov reg, reg].
				//
				else
				{
					fassert( exp->is_variable() );
				
					// Skip if not a register or branch dependant.
					//
					symbolic::variable rvar = exp->uid.get<symbolic::variable>();
					if ( rvar.is_branch_dependant || !rvar.is_register() )
						return;

					// If value is not alive, try hijacking the value declaration.
					//
					if ( !aux::is_alive( rvar, it, xblock, &ctracer ) )
					{
						// Must be a valid (and non-end) iterator.
						//
						if ( rvar.at.is_end() )
						{
							// If begin (begin&&end == invalid), fail.
							//
							if ( rvar.at.is_begin() )
								return;

							// Try determining the path to current block.
							//
							il_const_iterator it_rstr = rvar.at;
							it_rstr.restrict_path( it.container, true );
							std::vector<il_const_iterator> next = it_rstr.recurse( true );

							// If single direction possible, replace iterator, otherwise fail.
							//
							if ( next.size() == 1 )
								rvar.bind( next[ 0 ] );
							else
								return;
						}

						// Push to swap buffer.
						//
						ins_revive_swap_buffer.emplace_back( it, new_instruction, rvar );
					}
					else
					{
						// Push to swap buffer.
						//
						ins_swap_buffer.emplace_back( it, new_instruction, operand{ rvar.reg() } );
					}
				}
			});


		// Acquire lock and swap all instructions at once.
		//
		lock = {};
		cnd_unique_lock _g( mtx, xblock );

		for ( auto [it, ins, op] : ins_swap_buffer )
		{
			it->base = ins;
			it->operands = { it->operands[ 0 ], op };
			it->is_valid( true );
		}
		for ( auto [it, ins, var] : ins_revive_swap_buffer )
		{
			it->base = ins;

			auto& rev = revive_list[ var ];
			if ( !rev.is_valid() ) rev = aux::revive_register( var, it );
			it->operands = { it->operands[ 0 ], rev };
			it->is_valid( true );
		}
		return ins_swap_buffer.size() + ins_revive_swap_buffer.size();
	}
};