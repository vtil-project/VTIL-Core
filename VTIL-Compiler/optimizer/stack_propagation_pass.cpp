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
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Wrap cached tracer with a filter rejecting queries of registers and specializing recursive tracer.
	//
	struct lazy_tracer : cached_tracer
	{
		cached_tracer* link;
		il_const_iterator bypass = {};

		lazy_tracer( cached_tracer* p ) : link( p ) {}

		tracer* purify() override { return link; }

		symbolic::expression::reference trace( const symbolic::variable& lookup ) override
		{
			// If tracing stack pointer, use normal tracing.
			//
			if( lookup.is_register() && lookup.reg().is_stack_pointer() )
				return link->trace( lookup );

			// If instruction accesses memory:
			//
			if ( !lookup.at.is_end() && lookup.at->base->accesses_memory() )
			{
				// If query overlaps base, trace normally.
				//
				if ( lookup.is_register() && lookup.reg().overlaps( lookup.at->memory_location().first ) )
					return link->trace( lookup );
			}

			// Bypass if at the beginning of block//query.
			//
			if ( !bypass.is_valid() || lookup.at == bypass || lookup.at.is_end() )
				return cached_tracer::trace( lookup );

			// Return without tracing.
			//
			return lookup.to_expression();
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
		cached_tracer ctracer = {};
		lazy_tracer ltracer = { &ctracer };

		// Allocate the swap buffers.
		//
		std::vector<std::tuple<il_iterator, const instruction_desc*, operand>> ins_swap_buffer;
		std::vector<std::tuple<il_iterator, const instruction_desc*, symbolic::variable>> ins_revive_swap_buffer;

		// For each instruction:
		//
		for ( auto it = blk->begin(); !it.is_end(); it++ )
		{
			// Skip volatile instructions.
			//
			if ( it->is_volatile() ) continue;

			// Filter to LDD instructions referencing stack:
			//
			if ( it->base == &ins::ldd && it->memory_location().first.is_stack_pointer() )
			{
				auto resize_and_pack = [ & ] ( symbolic::expression::reference& exp )
				{
					exp = symbolic::variable::pack_all( exp.resize( it->operands[ 0 ].bit_count() ) );
				};

				// Lazy-trace the value.
				//
				symbolic::pointer ptr = { ctracer.trace( { it, REG_SP } ) + it->memory_location().second };
				symbolic::variable var = { it, { std::move( ptr ), it->access_size() } };
				ltracer.bypass = it;
				auto exp = xblock ? ltracer.rtrace( var ) : ltracer.trace( var );
				ltracer.bypass = {};

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
						continue;
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
						continue;

					// If value is not alive, try hijacking the value declaration.
					//
					if ( !aux::is_alive( rvar, it, xblock, nullptr ) )
					{
						// Must be a valid (and non-end) iterator.
						//
						if ( rvar.at.is_end() )
						{
							// If begin (begin&&end == invalid), fail.
							//
							if ( rvar.at.is_begin() )
								continue;

							// Try determining the path to current block.
							//
							il_const_iterator it_rstr = rvar.at;
							it_rstr.restrict_path( it.block, true );
							std::vector<il_const_iterator> next = it_rstr.recurse( true );

							// If single direction possible, replace iterator, otherwise fail.
							//
							if ( next.size() == 1 )
								rvar.bind( next[ 0 ] );
							else
								continue;
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
			}
		}

		// Acquire lock and swap all instructions at once.
		//
		lock = {};
		cnd_unique_lock _g( mtx, xblock );

		for ( auto [it, ins, op] : ins_swap_buffer )
		{
			( +it )->base = ins;
			( +it )->operands = { it->operands[ 0 ], op };
			it->is_valid( true );
		}
		for ( auto [it, ins, var] : ins_revive_swap_buffer )
		{
			( +it )->base = ins;

			register_desc rev;
			if ( auto i2 = xblock ? revive_list.find( var ) : revive_list.end(); i2 != revive_list.end() )
				rev = i2->second;
			else
				rev = aux::revive_register( var, it );

			( +it )->operands = { it->operands[ 0 ], rev };
			it->is_valid( true );
		}
		return ins_swap_buffer.size() + ins_revive_swap_buffer.size();
	}
};