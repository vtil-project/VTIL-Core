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
		return static_default;
	}
	const path_set& routine::get_path_bwd( const basic_block* src, const basic_block* dst ) const
	{
		if ( auto it = path_cache[ 1 ].find( dst ); it != path_cache[ 1 ].end() )
			if ( auto it2 = it->second.find( src ); it2 != it->second.end() )
				return it2->second;
		return static_default;
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

	// Finds a block in the list, get variant will throw if none found.
	//
	basic_block* routine::find_block( vip_t vip ) const
	{
		std::lock_guard g{ this->mutex };

		auto it = explored_blocks.find( vip );
		if ( it == explored_blocks.end() ) return nullptr;
		return it->second;
	}
	basic_block* routine::get_block( vip_t vip ) const
	{
		std::lock_guard g{ this->mutex };

		basic_block* block = find_block( vip );
		fassert( block );
		return block;
	}

	// Tries creating a new block bound to this routine.
	// - Mimics ::emplace, returns an additional bool reporting whether it's found or not.
	//
	std::pair<basic_block*, bool> routine::create_block( vip_t vip, basic_block* src )
	{
		std::lock_guard g{ this->mutex };

		// Try inserting into the map:
		//
		auto [it, inserted] = explored_blocks.emplace( vip, nullptr );
		basic_block*& block = it->second;
		if ( inserted )
		{
			// Create the block and set entry if none set.
			//
			block = new basic_block( this, vip );
			if ( !entry_point ) entry_point = block;
		}

		// Fix links and explore the path.
		//
		if ( src )
		{
			fassert( src->owner == this );
		
			bool new_next = std::find( src->next.begin(), src->next.end(), block ) == src->next.end();
			bool new_prev = inserted || std::find( block->prev.begin(), block->prev.end(), src ) == block->prev.end();

			if ( new_next ) src->next.emplace_back( block );
			if ( new_prev ) block->prev.emplace_back( src );

			if ( new_next || new_prev )
				explore_path( src, block );
		}
		else
		{
			explore_path( nullptr, block );
		}
		return { block, inserted };
	}

	// Deletes a block, should have no links or links must be nullified (no back-links).
	//
	void routine::delete_block( basic_block* block )
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

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

	// Provide basic statistics about the complexity of the routine.
	//
	size_t routine::num_blocks() const
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex }; 

		// Return the number of blocks.
		//
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
	size_t routine::num_branches() const
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Sum up paths in every block.
		//
		size_t n = 0;
		for ( auto& [_, blk] : explored_blocks )
			n += blk->next.size();
		return n;
	}

	// Routine structures free all basic blocks they own upon their destruction.
	//
	routine::~routine()
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		for ( auto& [vip, block] : explored_blocks )
		{
			block->next.clear();
			block->prev.clear();
			delete std::exchange( block, nullptr );
		}
	}

	// Clones the routine and it's every block.
	//
	routine* routine::clone() const
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Copy the routine.
		//
		auto copy = new routine( *this );
		
		// Clone each block referenced.
		//
		for ( auto& [vip, block] : copy->explored_blocks )
		{
			block = new basic_block( *block );
			block->owner = copy;
		}
		
		// Fix block links.
		//
		for ( auto& [vip, block] : copy->explored_blocks )
			for ( auto& list : { &block->next, &block->prev } )
				for ( auto& entry : *list )
					entry = copy->get_block( entry->entry_vip );
		copy->entry_point = copy->get_block( entry_point->entry_vip );

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
						std::inserter( new_set, new_set.begin() ),
						[ & ] ( const basic_block* block ) { return copy->get_block( block->entry_vip ); }
					);
					map_l2.emplace( copy->get_block( k2->entry_vip ), std::move( new_set ) );
				}
				map_l1.emplace( copy->get_block( k1->entry_vip ), std::move( map_l2 ) );
			}
			map = map_l1;
		}

		// Return the copy.
		//
		return copy;
	}
};
