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
#include "opaque_predicate_elimination_pass.hpp"
#include <vtil/symex>
#include <algorithm>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t opaque_predicate_elimination_pass::pass( basic_block* blk, bool xblock )
	{
		// If block is not complete, skip.
		//
		if ( !blk->is_complete() )
			return 0;

		// If branching to real, skip.
		//
		auto branch = std::prev( blk->end() );
		if ( !branch->base->is_branching_virt() )
			return 0;

		// Discover each possible branch target.
		//
		cached_tracer tmp = {};
		auto branch_targets = aux::discover_branches( blk, xblock ? &ctracer : &tmp, xblock );
		
		// For each destination block:
		//
		size_t cnt = 0;
		for ( auto it = blk->next.begin(); it != blk->next.end(); )
		{
			// Check if this destination is plausible or not.
			//
			vip_t target = ( *it )->entry_vip;
			bool impossible = true;
			for ( auto& [real, dst] : branch_targets )
				if ( !real )
					impossible &= ( dst != target ).get<bool>().value_or( false );
			
			// If it is not:
			//
			if ( impossible )
			{
				// Delete prev and next links.
				//
				( *it )->prev.erase( std::remove( ( *it )->prev.begin(), ( *it )->prev.end(), blk ), ( *it )->prev.end() );
				it = blk->next.erase( it );

				// Increment counter and continue.
				//
				cnt++;
				continue;
			}

			// Otherwise increment iterator and continue.
			//
			++it;
		}
		return cnt;
	}
	size_t opaque_predicate_elimination_pass::xpass( routine* rtn )
	{
		// Flush cached tracer.
		//
		ctracer.flush();

		// Invoke original method, if any removed:
		//
		if ( size_t cnt = pass_interface<>::xpass( rtn ) )
		{
			// Delete non-referenced blocks entirely.
			//
			for ( auto it = rtn->explored_blocks.begin(); it != rtn->explored_blocks.end(); )
			{
				if ( it->second->prev.size() == 0 )
					it = rtn->explored_blocks.erase( it );
				else
					++it;
			}

			// Return counter as is.
			//
			return cnt;
		}
		return 0;
	}
};