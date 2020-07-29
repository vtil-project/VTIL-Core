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
#include "dead_code_elimination_pass.hpp"
#include <vtil/utility>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Returns whether the instruction is a semantic equivalent of NOP or not.
	//
	static bool is_semantic_nop( const instruction& ins )
	{
		if ( ins.base == &ins::mov ||
			 ins.base == &ins::movsx )
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
		size_t counter = 0;

		if ( blk->empty() )
			return 0;

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
					symbolic::pointer ptr = { ctrace.trace_p( { it, base } ) + offset };
					if ( !( ptr.flags & register_stack_pointer ) )
						used = true;
					else
						used = aux::is_used( { it, {  ptr, it->access_size() } }, xblock, &ctrace );
				}
			}

			// If result is not used, nop it.
			//
			if ( !used )
			{
				( +it )->base = &ins::nop;
				( +it )->operands = {};
				counter++;
			}
		}

		// Purge simplifier cache since block iterators are invalided thus cache may fail.
		//
		ctrace.flush( blk );
		if ( counter != 0 )
			symbolic::purge_simplifier_cache();

		// Remove all nops.
		//
		for ( auto it = blk->begin(); !it.is_end(); )
		{
			if ( !it->is_volatile() && it->base == &ins::nop )
				it = blk->erase( it );
			else
				it++;
		}
		return counter;
	}
};