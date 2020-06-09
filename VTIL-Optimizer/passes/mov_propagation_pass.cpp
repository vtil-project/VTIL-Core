#include "mov_propagation_pass.hpp"
#include <vtil/query>
#include "../auxiliaries.hpp"

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
		symbolic::expression trace( symbolic::variable lookup ) override
		{
			// If at bypass point or at the end (due to recursion, invoke original).
			//
			if ( lookup.at == bypass || lookup.at.is_end() )
				return cached_tracer::trace( std::move( lookup ) );

			// If at move:
			//
			if ( *lookup.at->base == ins::mov )
			{
				// Return source as is.
				//
				auto& src = lookup.at->operands[ 1 ];
				if ( src.is_register() )
					return symbolic::variable{ lookup.at, src.reg() }.to_expression();
				else
					return { src.imm().u64, ( bitcnt_t ) src.size() * 8 };
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
		size_t counter = 0;
		mov_tracer mtracer = {};
		cached_tracer ctracer = {};

		// Iterate each instruction:
		//
		for ( auto it = blk->begin(); it != blk->end(); it++ )
		{
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
					// Replace the operand with a constant.
					//
					op = { *res.get(), ( bitcnt_t ) op.size() * 8 };
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

					// Skip if value is dead, otherwise replace operand.
					//
					if ( !aux::is_alive( var, it, &ctracer ) )
						continue;
					op = var.reg();
				}

				// Validate modification and increment counter.
				//
				fassert( it->is_valid() );
				counter++;
			}
		}
		return counter;
	}
};
