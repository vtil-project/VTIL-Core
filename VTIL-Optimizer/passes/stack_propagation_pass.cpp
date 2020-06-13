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
#include "stack_propagation_pass.hpp"
#include <vtil/query>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Wrap cached tracer with a filter rejecting queries of registers and specializing recursive tracer.
	//
	struct lazy_tracer : cached_tracer
	{
		symbolic::expression trace( symbolic::variable lookup ) override
		{
			size_t idx_special = lookup.at.container->last_temporary_index + 1;

			// If register:
			//
			if ( lookup.is_register() )
			{
				// If stack pointer:
				//
				if ( lookup.reg().is_stack_pointer() )
				{
					// If index 0, return as is.
					//
					uint32_t sp_index = lookup.at.is_end() ? lookup.at.container->sp_index : lookup.at->sp_index;
					if ( sp_index == 0 )
						return symbolic::variable{ lookup.at.container->begin(), REG_SP }.to_expression();

					// Otherwise, return unique pseudo-register per stack instance.
					//
					register_desc desc = {
						register_local,
						sp_index + idx_special,
						lookup.reg().bit_count
					};
					return symbolic::variable{ lookup.at.container->begin(), desc }.to_expression();
				}

				// Otherwise, return without tracing.
				//
				if( !lookup.at.is_end() )
					return lookup.to_expression();
			}

			// Fallback to default tracer.
			//
			return cached_tracer::trace( std::move( lookup ) );
		}

		symbolic::expression rtrace( symbolic::variable lookup, int64_t limit = -1 ) override
		{
			// Invoke default tracer and store the result.
			//
			symbolic::expression result = trace( std::move( lookup ) );
			
			// If result is a variable:
			//
			if ( result.is_variable() )
			{
				// If result is a non-local memory variable, invoke rtrace primitive.
				//
				auto& var = result.uid.get<symbolic::variable>();
				if ( var.is_memory() && !aux::is_local( var.mem().decay() ) )
					return tracer::rtrace( var, limit );
			}
			return result;
		}
	};

	// Implement the pass.
	//
	size_t stack_propagation_pass::pass( basic_block* blk, bool xblock )
	{
		size_t counter = 0;
		lazy_tracer ltracer = {};
		cached_tracer ctracer = {};

		// => Begin a foward iterating query.
		//
		query::create( blk->begin(), +1 )

			// >> Skip volatile instructions.
			.where( [ ] ( instruction& ins ) { return !ins.is_volatile(); } )
		
			// | Filter to LDD instructions referencing stack:
			.where( [ ] ( instruction& ins ) { return *ins.base == ins::ldd && ins.memory_location().first.is_stack_pointer(); } )

			// := Project back to iterator type.
			.unproject()
		
			// @ For each:
			.for_each( [ & ] ( const il_iterator& it )
			{
				constexpr auto is_convertable = [ ] ( const symbolic::expression& exp )
				{
					// If not a single variable, fail.
					//
					if ( exp.is_expression() &&
						 ( exp.op != math::operator_id::cast || !exp.lhs->is_variable() ) &&
						 ( exp.op != math::operator_id::ucast || !exp.lhs->is_variable() ) )
						return false;

					// If memory variable, fail.
					//
					if ( exp.is_variable() && exp.uid.get<symbolic::variable>().is_memory() )
						return false;
					return true;
				};
				auto resize_and_pack = [ & ] ( symbolic::expression& exp )
				{
					exp = symbolic::variable::pack_all( exp.resize( it->operands[ 0 ].bit_count() ) );
				};

				// Lazy-trace the value.
				//
				symbolic::pointer ptr = { ltracer( { it, REG_SP } ) + it->memory_location().second };
				symbolic::variable var = { it, { ptr, bitcnt_t( it->access_size() * 8 ) } };
				symbolic::expression exp = xblock ? ltracer.rtrace( var ) : ltracer.trace( var );

				// Resize and pack variables.
				//
				resize_and_pack( exp );

				// If result is a non-convertable expression, try usual tracing.
				//
				if ( !is_convertable( exp ) )
				{
					var.mem().base = { ctracer( { it, REG_SP } ) + it->memory_location().second };
					exp = xblock ? ctracer.rtrace( var ) : ctracer.trace( var );
					resize_and_pack( exp );
				}

				// Determine the instruction we will use to move the source.
				//
				auto* new_instruction = &ins::mov;
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
				}
				// Otherwise, try to replace with [mov reg, reg].
				//
				else
				{
					fassert( exp.is_variable() );
				
					// Skip if not a register or branch dependant.
					//
					symbolic::variable& var = exp.uid.get<symbolic::variable>();
					if ( var.is_branch_dependant || !var.is_register() )
						return;
					register_desc reg = var.reg();

					// If value is not alive, try hijacking the value declaration.
					//
					if ( !aux::is_alive( var, it, &ctracer ) )
					{
						// Must be a valid (and non-end) iterator.
						//
						if ( var.at.is_end() )
						{
							// If begin (begin&&end == invalid), fail.
							//
							if ( var.at.is_begin() )
								return;

							// Try determining the path to current block.
							//
							il_const_iterator it_rstr = var.at;
							it_rstr.restrict_path( it.container, true );
							std::vector<il_const_iterator> next = it_rstr.recurse( true );

							// If single direction possible, replace iterator, otherwise fail.
							//
							if ( next.size() == 1 )
								var.bind( next[ 0 ] );
							else
								return;
						}
						reg = aux::revive_register( var, it );
					}

					// Replace with a mov.
					//
					it->base = new_instruction;
					it->operands = { it->operands[ 0 ], reg };
				}

				// Validate modification and increment counter.
				//
				fassert( it->is_valid() );
				counter++;
			});
		return counter;
	}
};