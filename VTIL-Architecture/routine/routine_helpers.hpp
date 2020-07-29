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
#pragma once
#include <type_traits>
#include <vtil/utility>
#include "basic_block.hpp"
#include "routine.hpp"

namespace vtil
{
	namespace impl
	{
		// Takes an additional visitor compared to original, returns true if it should break from all.
		//
		template<typename callback, typename iterator_type, bool fwd, typename visit_callback>
		static bool enumerate_instructions( callback&& fn, iterator_type it, const iterator_type& dst, const iterator_type& origin, visit_callback& visit, bool first = false )
		{
			// Until we reach the destination:
			//
			const std::vector<basic_block*>* links = nullptr;
			while ( it != dst && it.is_valid() )
			{
				// If we reached the beginning of the block, set links and break.
				// - Backward.
				//
				if constexpr ( !fwd )
				{
					if ( it.is_begin() )
					{
						links = &it.block->prev;
						break;
					}
					--it;
				}

				// If we're back to origin and this is not the first call, break.
				//
				if ( !first && it == origin )
					break;

				// Invoke callback, break if requested so.
				//
				enumerator::tagged_order order = enumerator::invoke( fn, it );
				if ( order.should_break )
					return order.global_break;

				// If we reached the end of the block, set links and break.
				// - Forward.
				//
				if constexpr ( fwd )
				{
					++it;
					if ( it.is_end() )
					{
						links = &it.block->next;
						break;
					}
				}
			}

			// Recurse.
			//
			if ( links && !links->empty() )
			{
				constexpr auto make_it = [ ] ( basic_block* blk ) -> iterator_type 
				{ 
					return fwd ? blk->begin() : blk->end(); 
				};

				// If there is a single link, forward functor instead of copying.
				//
				if ( links->size() == 1 )
				{
					return visit( links->front() )
						&& enumerate_instructions<callback, iterator_type, fwd>( std::forward<callback>( fn ), make_it( links->front() ), dst, origin, visit );
				}
				else
				{
					// For each link:
					//
					for ( basic_block* blk : *links )
					{
						// Skip if we should not visit.
						//
						if ( !visit( blk ) )
							continue;

						// Invoke enumerator, propagate value if true.
						//
						if ( enumerate_instructions<callback, iterator_type, fwd>( make_copy<callback>( fn ), make_it( blk ), dst, origin, visit ) )
							return true;
					}
				}
			}
			return false;
		}
	};

	// Enumerates every instruction in the routine forward/backward, within the boundaries if specified.
	// - Fwd: [src, dst) || [src, any vexit]
	// - Bwd: [src, dst) || [src, entry point]
	//
	template<typename callback, typename iterator_type>
	void routine::enumerate( callback fn, const iterator_type& src, const iterator_type& dst ) const
	{
		// Allocate a visit list and fetch allowed list for the path if relevant.
		//
		path_set set = {};
		const path_set* set_allowed;
		if ( dst.is_valid() )
		{
			set_allowed = &src.block->owner->get_path( src.block, dst.block );
			set.reserve( set_allowed->size() );
		}
		else
		{
			set_allowed = nullptr;
			set.reserve( src.block->owner->num_blocks() );
		}

		// Declare visitor and check if we have a path from dst to src if constraint.
		//
		auto visitor = [ & ] ( basic_block* blk )
		{
			// Should be in allowed list if relevant.
			//
			if ( set_allowed && !set_allowed->contains( blk ) )
				return false;
			if ( src.is_path_restricted && ( !src.paths_allowed || !src.paths_allowed->contains( blk ) ) )
				return false;

			// Should not be in path-set.
			//
			return set.emplace( blk ).second;
		};
		if ( set_allowed && set_allowed->empty() ) return;

		// Begin enumeration.
		//
		impl::enumerate_instructions<callback, iterator_type, true>
		(
			std::move( fn ), 
			src,
			dst,
			src,
			visitor,
			true
		);
	}
	template<typename callback, typename iterator_type>
	void routine::enumerate_bwd( callback fn, const iterator_type& src, const iterator_type& dst ) const
	{
		// Allocate a visit list and fetch allowed list for the path if relevant.
		//
		path_set set = {};
		const path_set* set_allowed;
		if ( dst.is_valid() )
		{
			set_allowed = &src.block->owner->get_path_bwd( src.block, dst.block );
			set.reserve( set_allowed->size() );
		}
		else
		{
			set_allowed = nullptr;
			set.reserve( src.block->owner->num_blocks() );
		}
		
		// Declare visitor and check if we have a path from dst to src if constraint.
		//
		auto visitor = [ & ] ( basic_block* blk )
		{
			// Should be in allowed list if relevant.
			//
			if ( set_allowed && !set_allowed->contains( blk ) )
				return false;
			if ( src.is_path_restricted && ( !src.paths_allowed || !src.paths_allowed->contains( blk ) ) )
				return false;

			// Should not be in path-set.
			//
			return set.emplace( blk ).second;
		};
		if ( set_allowed && set_allowed->empty() ) return;

		// Begin enumeration.
		//
		impl::enumerate_instructions<callback, iterator_type, false>
		(
			std::move( fn ), 
			src, 
			dst,
			src,
			visitor,
			true
		);
	}
};