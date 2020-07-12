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
#include "routine.hpp"
#include "basic_block.hpp"

namespace vtil
{
	// Gets (forward/backward) path from src to dst.
	//
	const path_set& routine::get_path( const basic_block* src, const basic_block* dst ) const
	{
		if ( auto it = path_cache[ 0 ].find( src ); it != path_cache[ 0 ].end() )
			if ( auto it2 = it->second.find( dst ); it2 != it->second.end() )
				return it2->second;
		return make_default<path_set>();
	}
	const path_set& routine::get_path_bwd( const basic_block* src, const basic_block* dst ) const
	{
		if ( auto it = path_cache[ 1 ].find( dst ); it != path_cache[ 1 ].end() )
			if ( auto it2 = it->second.find( src ); it2 != it->second.end() )
				return it2->second;
		return make_default<path_set>();
	}

	// Simple helpers to check if (forward/backward) path from src to dst exists.
	//
	bool routine::has_path( const basic_block* src, const basic_block* dst ) const
	{
		return get_path( src, dst ).size() != 0;
	}
	bool routine::has_path_bwd( const basic_block* src, const basic_block* dst ) const
	{
		return get_path( src, dst ).size() != 0;
	}

	// Checks whether the block is in a loop.
	//
	bool routine::is_looping( const basic_block* blk ) const
	{
		for ( auto next : blk->next )
			if ( has_path( next, blk ) )
				return true;
		return false;
	}
	// Explores the given path, reserved for internal use.
	//
	void routine::explore_path( const basic_block* src, const basic_block* dst )
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Insert self-referential links.
		//
		path_cache[ 0 ][ dst ][ dst ].insert( dst );
		path_cache[ 1 ][ dst ][ dst ].insert( dst );

		// If source is given:
		//
		if ( src )
		{
			// If foward path is already explored, skip.
			//
			if ( path_cache[ 0 ][ src ].contains( dst ) )
				return;

			// Insert direct links.
			//
			auto& fwd = path_cache[ 0 ][ src ][ dst ];
			fwd.insert( src ); fwd.insert( dst );
			auto& bwd = path_cache[ 1 ][ dst ][ src ];
			bwd.insert( src ); bwd.insert( dst );

			// Forward propagate.
			//
			for ( auto& [prev, level2] : path_cache[ 0 ] )
			{
				for ( auto& [next, paths] : level2 )
				{
					if ( next == src )
					{
						auto& propagated_link = path_cache[ 0 ][ prev ][ dst ];
						propagated_link.insert( paths.begin(), paths.end() );
						propagated_link.insert( dst );
					}
				}
			}
			// Backwards propagate.
			//
			for ( auto& [prev, level2] : path_cache[ 1 ] )
			{
				for ( auto& [next, paths] : level2 )
				{
					if ( prev == dst )
					{
						auto& propagated_link = path_cache[ 1 ][ src ][ next ];
						propagated_link.insert( paths.begin(), paths.end() );
						propagated_link.insert( src );
					}
				}
			}
		}

		// Recurse.
		//
		for ( auto next : dst->next )
			explore_path( dst, next );
	}

	// Flushes the path cache, reserved for internal use.
	//
	void routine::flush_paths()
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Invoke from entry point.
		//
		path_cache[ 0 ].clear();
		path_cache[ 1 ].clear();
		explore_path( nullptr, entry_point );
	}

	// Deletes a block, should have no links or links must be nullified (no back-links).
	//
	void routine::delete_block( basic_block* block )
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Assert that links are nullified.
		//
		for ( auto nxt : block->next )
			fassert( std::find( nxt->prev.begin(), nxt->prev.end(), block ) == nxt->prev.end() );
		for ( auto nxt : block->prev )
			fassert( std::find( nxt->next.begin(), nxt->next.end(), block ) == nxt->next.end() );

		// Enumerate both forwards and backwards caches.
		//
		for ( auto& cache : path_cache )
		{
			// Enumerate path_map.
			//
			for ( auto it = cache.begin(); it != cache.end(); )
			{
				// If entry key references deleted block, erase it and continue.
				//
				if ( it->first == block )
				{
					it = cache.erase( it );
					continue;
				}

				// Enumerate std::map<const basic_block*, path_set>
				//
				for ( auto it2 = it->second.begin(); it2 != it->second.end(); )
				{
					// If entry key references deleted block, erase it and continue.
					//
					if ( it2->first == block )
					{
						it2 = it->second.erase( it2 );
						continue;
					}

					// Remove any references from set.
					//
					it2->second.erase( block );

					// Continue iteration.
					//
					it2++;
				}

				// Continue iteration.
				//
				it++;
			}
		}

		// Remove from explored blocks and delete it.
		//
		explored_blocks.erase( block->entry_vip );
		delete block;
	}


	// Returns the number of basic blocks and instructions in the routine.
	//
	size_t routine::num_blocks() const
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex }; 
		return explored_blocks.size();
	}
	size_t routine::num_instructions() const
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Sum up instructions in every block.
		//
		size_t n = 0;
		for ( auto& [_, blk] : explored_blocks )
			n += blk->size();
		return n;
	}

	// Routine structures free all basic blocks they own upon their destruction.
	//
	routine::~routine()
	{
		for ( auto [vip, block] : explored_blocks )
			delete block;
	}

	// Clones the routine and it's every block.
	//
	routine* routine::clone() const
	{
		routine* copy = new routine{ this->arch_id };

		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Copy the context data.
		//
		copy->context = this->context;

		// Copy calling conventions.
		//
		copy->routine_convention = this->routine_convention;
		copy->subroutine_convention = this->subroutine_convention;
		copy->spec_subroutine_conventions = this->spec_subroutine_conventions;

		// Copy internally tracked stats.
		//
		copy->local_opt_count = this->local_opt_count.load();
		copy->last_internal_id = this->last_internal_id.load();

		// Create a recursive clone helper and call into it with entry point.
		//
		const std::function<basic_block*(const basic_block*)> reference_block = 
			[ & ] ( const basic_block* src ) -> basic_block*
		{
			// If already indexed, return as is.
			//
			basic_block*& index = copy->explored_blocks[ src->entry_vip ];
			if ( index ) return index;
			
			// Copy the block and fix it's references.
			//
			index = new basic_block{ *src };
			index->owner = copy;
			
			for ( basic_block*& next : index->next )
				next = reference_block( next );
			for ( basic_block*& prev : index->prev )
				prev = reference_block( prev );
			return index;
		};
		copy->entry_point = reference_block( this->entry_point );

		// Iterate each explored block to make sure we've covered all.
		//
		for ( auto& [vip, block] : this->explored_blocks )
			fassert( copy->explored_blocks[ vip ] == reference_block( block ) );

		// Copy path cache.
		//
		copy->path_cache[ 0 ] = this->path_cache[ 0 ];
		copy->path_cache[ 1 ] = this->path_cache[ 1 ];
		for ( path_map& map : copy->path_cache )
		{
			path_map map_l1 = {};
			for ( auto& [k1, v] : map )
			{
				std::unordered_map<const basic_block*, path_set, hasher<>> map_l2;
				for ( auto& [k2, set] : v )
				{
					path_set new_set;
					std::transform(
						set.begin(), set.end(),
						std::inserter( new_set, new_set.begin() ), reference_block
					);
					map_l2.emplace( reference_block( k2 ), std::move( new_set ) );
				}
				map_l1.emplace( reference_block( k1 ), std::move( map_l2 ) );
			}
			map = map_l1;
		}

		// Return the copy.
		//
		return copy;
	}
};
