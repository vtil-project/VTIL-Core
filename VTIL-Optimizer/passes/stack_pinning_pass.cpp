#include "stack_pinning_pass.hpp"
#include <vtil/query>
#include <numeric>

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t stack_pinning_pass::pass( basic_block* blk, bool xblock )
	{
		size_t counter = 0;
		cached_tracer ctrace = {};
		
		// => Begin a foward iterating query.
		//
		query::create( blk->begin(), +1 )

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

				// If it simplifies to a constant:
				//
				if ( auto shift_offset = ( sp_next - sp_curr ).get<int64_t>() )
				{
					// Replace with a stack shift.
					//
					it->base = &ins::vpinr;
					it->operands = { { REG_SP } };
					blk->shift_sp( *shift_offset, true, it );

					// Flush tracer cache.
					//
					ctrace.flush();

					// Validate modification and increment counter.
					//
					fassert( it->is_valid() );
					counter++;
				}
			} );

		// TODO: Fix
		//
		// Iterate each instruction:
		//
		/*for( auto i1 = blk->begin(); i1 != blk->end(); i1++ )
		{
			// Find the first instruction accesing $sp.
			//
			auto it = std::find_if( i1, blk->end(), [ & ] ( const instruction& ins )
			{
				static const auto indices = [ ] () {
					std::array<size_t, VTIL_ARCH_MAX_OPERAND_COUNT> arr;
					std::iota( arr.begin(), arr.end(), 0 );
					return arr;
				}();

				// If stack index is changed, return.
				//
				if ( ins.sp_index != i1->sp_index )
					return true;
				
				for ( auto [op, idx] : zip( ins.operands, indices ) )
				{
					// Skip if memory location since it's virtual $sp in that case.
					//
					if ( idx == ins.base->memory_operand_index )
						continue;

					// If operand is stack pointer, declare found.
					//
					if ( op.is_register() && op.reg().is_stack_pointer() )
						return true;
				}
				return false;
			} );

			// Pin the stack offset for the range.
			//
			if ( it != i1 )
			{
				int64_t new_sp_offset = it.is_end() && blk->sp_index == i1->sp_index ? blk->sp_offset : it->sp_offset;
				for ( auto i2 = i1; i2 != it; i2++ )
				{
					if ( i2->sp_offset != new_sp_offset )
					{
						i2->sp_offset = new_sp_offset;
						counter++;
					}
				}
				i1 = it;
				if ( i1 == blk->end() ) break;
			}
		}*/

		return counter;
	}
};