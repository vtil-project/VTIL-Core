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
#include "eliminate_dead.hpp"

namespace vtil::optimizer
{
	// Checks if the instruction's result is unused, strictly requires the 
	// instructions after the specified iterator to be "optimized" already.
	//
	static bool is_dead( const il_const_iterator& ins, bool keep_virtual )
	{
		// Do not kill volatiles, memory writes and branches.
		//
		if ( ins->is_volatile() || ins->base->writes_memory() || ins->base->is_branching() )
			return false;

		// For each operand:
		//
		for ( int i = 0; i < ins->base->operand_count(); i++ )
		{
			// Skip if not written to.
			//
			if ( ins->base->operand_types[ i ] < operand_type::write )
				continue;

			// Resolve the register it writes to.
			//
			auto& reg = ins->operands[ i ].reg();

			// Determine the state of the result.
			//
			uint64_t value_mask = reg.get_mask();
			uint64_t read_mask = 0;
			for ( auto it = std::next( ins ); !it.is_end(); it++ )
			{
				if ( int op = it->reads_from( reg ) )
					read_mask |= value_mask & it->operands[ op - 1 ].reg().get_mask();
				if ( int op = it->writes_to( reg ) )
					value_mask &= ~it->operands[ op - 1 ].reg().get_mask();
			}

			// If value is read, skip the elimination.
			//
			if ( read_mask )
				return false;

			// If value is not overwritten:
			//
			if ( value_mask )
			{
				// If physical register or virtual where requested so,
				// skip the elimination.
				//
				if ( reg.is_physical() ) return false;
				if ( keep_virtual && reg.is_virtual() ) return false;
			}

			// Result is dead, break out of the loop.
			//
			break;
		}
		return true;
	}

	// Eliminates all instructions where the result is not used by the
	// next block or the exited routine.
	//
	size_t dead_elimination_pass::pass( basic_block* blk, bool xblock )
	{
		// Skip if the block is empty.
		//
		if ( !blk->size() )
			return 0;

		// Keep virtual registers if not branching to real.
		//
		auto it = std::prev( blk->end() );
		bool keep_virtual = !it->base->is_branching_real();

		// Remove dead instructions starting from the back.
		//
		size_t counter = 0;
		do
		{
			if ( is_dead( it, keep_virtual ) )
				counter++, it = blk->erase( it );
		}
		while ( !it.is_begin() && ( --it, true ) );
		return counter;
	}
}