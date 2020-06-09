#include "dead_code_elimination_pass.hpp"
#include <vtil/query>
#include <vtil/utility>
#include "../auxiliaries.hpp"

namespace vtil::optimizer
{
	// Returns whether the instruction is a semantic equivalent of NOP or not.
	//
	static bool is_semantic_nop( const instruction& ins )
	{
		if ( *ins.base == ins::mov ||
			 *ins.base == ins::movsx )
		{
			if ( ins.operands[ 0 ] == ins.operands[ 1 ] )
				return true;
		}

		return false;
	}

	// Implement the pass.
	//
	size_t dead_code_elimination_pass::pass( basic_block* blk, bool xblock )
	{
		if ( blk->size() == 0 )
			return 0;

		cached_tracer ctrace = {};
		size_t counter = 0;

		// If cross-block, first try local.
		//
		if ( xblock )
			counter += pass( blk, false );

		auto [rbegin, rend] = reverse_iterators( *blk );
		for ( auto it = rbegin; it != rend; ++it )
		{
			// Skip if volatile or branching.
			//
			if ( it->base->is_branching() || it->is_volatile() )
				continue;

			// Check if results are used if not semantically nop.
			//
			bool used = false;
			if ( !is_semantic_nop( *it ) )
			{
				// Check register results:
				//
				for ( auto [op, type] : it->enum_operands() )
				{
					// Skip if not written to.
					//
					if ( type < operand_type::write )
						continue;

					// Create symbolic variable.
					//
					symbolic::variable var = { it, op.reg() };
					if ( used = aux::is_used( var, xblock, &ctrace ) )
						break;
				}

				// Check memory results:
				//
				if ( !used && it->base->writes_memory() )
				{
					auto [base, offset] = it->memory_location();
					symbolic::variable var = { it, 
					{ 
						{ ctrace.trace_p( { it, base } ) + offset }, 
						bitcnt_t( it->access_size() * 8 ) 
					} };
					used = aux::is_used( var, xblock, &ctrace );
				}
			}

			// If result is not used, nop it.
			//
			if ( !used )
			{
				it->base = &ins::nop;
				it->operands = {};
				counter++;
			}
		}

		// Remove all nops.
		//
		for ( auto it = blk->begin(); it != blk->end(); )
		{
			if ( !it->is_volatile() && *it->base == ins::nop )
				it = blk->erase( it );
			else
				it++;
		}
		return counter;
	}
};