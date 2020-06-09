#include "istack_ref_substitution_pass.hpp"
#include <vtil/query>

namespace vtil::optimizer 
{
	// Implement the pass.
	//
	size_t istack_ref_substitution_pass::pass( basic_block* blk, bool xblock )
	{
		size_t counter = 0;
		cached_tracer ctrace = {};

		// => Begin a foward iterating query.
		//
		query::create( blk->begin(), + 1 )

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
				auto delta = ctrace( { it, it->memory_location().first } ) - ctrace( { it, REG_SP } );

				// If successful, replace the operands.
				//
				if ( auto stack_offset = delta.get<int64_t>() )
				{
					it->operands[ it->base->memory_operand_index ] = { REG_SP };
					it->operands[ it->base->memory_operand_index + 1 ].imm().i64 += *stack_offset;

					// Validate modification and increment counter.
					//
					fassert( it->is_valid() );
					counter++;
				}
			} );
		return counter;
	}
}
