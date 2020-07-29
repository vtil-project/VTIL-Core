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
#include "register_renaming_pass.hpp"
#include <vtil/symex>
#include <algorithm>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t register_renaming_pass::pass( basic_block* blk, bool xblock )
	{
		size_t cnt = 0;
		cached_tracer tracer = {};

		// For each instruction:
		//
		for ( auto it = blk->begin(); !it.is_end(); it++ )
		{
			// If not [mov regN regN / movsx regN regN], skip.
			//
			if ( ( *it->base != ins::mov && *it->base != ins::movsx ) ||
				 !it->operands[ 0 ].is_register() || !it->operands[ 1 ].is_register() ||
				 it->operands[ 0 ].reg().bit_count != it->operands[ 1 ].reg().bit_count )
				continue;
			
			// Discard path restriction.
			//
			it.clear_restrictions();

			// Skip if non-position bound.
			//
			symbolic::variable dst = { it, it->operands[ 0 ].reg() };
			symbolic::variable src = { it, it->operands[ 1 ].reg() };
			if ( !src.at.is_valid() || !dst.at.is_valid() || dst.reg().is_stack_pointer() )
				continue;

			// If src is used after this point, skip.
			//
			if ( aux::is_used( src, xblock, &tracer ) )
				continue;

			// Path restrict iterator if not cross-block.
			//
			if( !xblock ) it.restrict_path();
			
			// Iterate backwards:
			//
			std::unordered_set<il_iterator> pending, results;
			auto fail = [ & ] () { pending.insert( {} ); return enumerator::obreak_r; };
			it.block->owner->enumerate_bwd( [ &, mask = math::fill( it->operands[ 1 ].reg().bit_count ), lpending = il_iterator{} ]( const il_iterator& i ) mutable
			{
				// Clear pending if relevant.
				//
				if ( lpending.is_valid() )
					pending.erase( possess_value( lpending ) );

				// If we're at a branch, validate is_used again.
				//
				if ( i->base->is_branching() && i.block->next.size() != 1 )
					if ( aux::is_used( src.bind( i ), xblock, &tracer ) )
						return fail();

				// If it does not access source, skip.
				//
				if ( auto details = src.accessed_by( i, nullptr ) )
				{
					// If unknown access, fail.
					//
					if ( details.is_unknown() )
						return fail();

					// If out-of-bounds access, fail.
					//
					if ( details.bit_offset < 0 || ( details.bit_count + details.bit_offset ) > it->operands[ 1 ].reg().bit_count )
						return fail();

					// If source is being overwritten, clear the mask.
					//
					if ( details.write && !details.read )
						mask &= ~math::fill( details.bit_count, details.bit_offset );

					// If source is being accessed by a volatile instruction, fail.
					//
					if ( i->is_volatile() )
						return fail();
				}

				// If destination is used by the instruction, fail.
				// Can be ignored if mask is cleared.
				//
				if ( dst.accessed_by( i, nullptr ) && mask )
					return fail();

				// Skip if mask is not cleared.
				//
				if ( mask )
				{
					// If at begin, add to pending.
					//
					pending.insert( i );
					lpending = i;
					return enumerator::ocontinue;
				}

				// If dst is used after this point, fail.
				//
				results.insert( i );
				return aux::is_used( dst.bind( i ), xblock, nullptr ) ? fail() : enumerator::obreak;
			}, dst.reg().is_local() ? it.restrict_path() : it );

			// If query failed, skip.
			//
			if ( !pending.empty() || results.empty() )
				continue;

			// For each edge node:
			//
			for ( il_iterator it_begin : results )
			{
				// Restrict iterator path and iterate forward.
				//
				it_begin.restrict_path( it.block, true );
				it.block->owner->enumerate( [ & ] ( const il_iterator& it )
				{
					// Iterate each operand:
					//
					for ( auto& op : ( +it )->operands )
					{
						// Skip if not register or not overlapping with source.
						//
						if ( !op.is_register() ) continue;
						auto& reg = op.reg();
						if ( !reg.overlaps( src.reg() ) ) continue;

						// Swap with destination register.
						//
						reg.combined_id = dst.reg().combined_id;
						reg.flags = dst.reg().flags;
						reg.bit_offset += dst.reg().bit_offset - src.reg().bit_offset;
					}
					( +it )->is_valid( true );

				}, it_begin, it );

				// Nop the origin instruction.
				//
				( +it )->base = &ins::nop;
				( +it )->operands = {};
				cnt++;
				tracer.flush();
			}
		}

		// TODO: Compress register space!
		//
		return cnt;
	}
};