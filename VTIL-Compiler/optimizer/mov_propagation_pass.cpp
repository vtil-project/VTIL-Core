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
#include "mov_propagation_pass.hpp"
#include <vtil/query>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Implement a mov tracer that does not trace any symbolic operations.
	//
	struct mov_tracer : cached_tracer
	{
		// Declare an iterator that is exempt from this restriction, which is the query origin.
		//
		il_const_iterator bypass = {};

		// Override tracer.
		//
		symbolic::expression trace( const symbolic::variable& lookup ) override
		{
			// If at bypass point or at the end (due to recursion, invoke original).
			//
			if ( lookup.at == bypass || lookup.at.is_end() )
				return cached_tracer::trace( lookup );

			// If at move:
			//
			if ( lookup.at->base == &ins::mov )
			{
				// If destination is overlapping lookup variable:
				//
				auto& dst = lookup.at->operands[ 0 ].reg();
				if ( lookup.is_register() && lookup.reg().overlaps( dst ) )
				{
					// If no unknown bits after mov:
					//
					if ( ( lookup.reg().get_mask() & dst.get_mask() ) == lookup.reg().get_mask() )
					{
						// If source isn't stack pointer.
						//
						auto& src = lookup.at->operands[ 1 ];
						if ( src.is_immediate() || !src.reg().is_stack_pointer() )
						{
							// Create a symbolic expression for the source.
							//
							symbolic::expression result;
							if ( src.is_register() )
								result = symbolic::variable{ lookup.at, src.reg() }.to_expression();
							else
								result = { src.imm().u64, src.bit_count() };

							// Shift and resize accordingly and return.
							//
							result = result >> ( lookup.reg().bit_offset - dst.bit_offset );
							return result.resize( lookup.reg().bit_count );
						}
					}
				}
			}

			// Otherwise, return the lookup expression and skip tracing.
			//
			return lookup.to_expression();
		}
	};

	// Implement the pass.
	//
	size_t mov_propagation_pass::pass( basic_block* blk, bool xblock )
	{
		// Acquire a shared lock.
		//
		cnd_shared_lock lock( mtx, xblock );

		// Create tracers.
		//
		cached_tracer ctracer = {};
		mov_tracer mtracer = {};
		
		// Allocate the swap buffer.
		//
		std::vector<std::pair<operand*, operand>> operand_swap_buffer;

		// Iterate each instruction:
		//
		for ( auto it = blk->begin(); it != blk->end(); it++ )
		{
			// Skip if volatile.
			//
			if ( it->is_volatile() )
				continue;

			// Enumerate each operand:
			//
			for ( auto [op, type] : it->enum_operands() )
			{
				// Skip if being written to or if immediate.
				//
				if ( type >= operand_type::write || !op.is_register() )
					continue;

				// Declare bypass point and trace it.
				//
				mtracer.bypass = it;
				auto res = xblock ? mtracer.rtrace_p( { it, op.reg() } ) : mtracer.trace_p( { it, op.reg() } );

				// Skip if invalid result or if we resolved it into an expression.
				//
				if ( res.is_expression() || !res.is_valid() )
					continue;

				// If constant:
				//
				if ( res.is_constant() )
				{
					// If operand does not accept immediates, skip.
					//
					if ( type != operand_type::read_any )
						continue;

					// Replace the operand with a constant.
					//
					operand_swap_buffer.emplace_back( &op, operand{ *res.get(), op.bit_count() } );
				}
				// If variable:
				//
				else
				{
					// Skip if not register.
					//
					auto& var = res.uid.get<symbolic::variable>();
					if ( !var.is_register() )
						continue;
					auto& reg = var.reg();

					// Skip if stack pointer or if equivalent.
					//
					if ( reg.is_stack_pointer() || reg == op.reg() )
						continue;

					// Skip if value is dead.
					//
					if ( !aux::is_alive( var, it, xblock, &ctracer ) )
						continue;

					// Push to swap buffer.
					//
					operand_swap_buffer.emplace_back( &op, operand{ var.reg() } );
				}
			}
		}

		// Acquire lock and swap all operands at once.
		//
		lock = {};
		cnd_unique_lock _g( mtx, xblock );
		for ( auto [dst, op] : operand_swap_buffer )
		{
			*dst = op;
			fassert( dst->is_valid() );
		}
		return operand_swap_buffer.size();
	}
};
