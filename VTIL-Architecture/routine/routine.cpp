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
		if ( auto it = path_cache.find( src ); it != path_cache.end() )
			if ( auto it2 = it->second.find( dst ); it2 != it->second.end() )
				return it2->second;
		return static_default;
	}

	// Simple helpers to check if (forward/backward) path from src to dst exists.
	//
	bool routine::has_path( const basic_block* src, const basic_block* dst ) const
	{
		return !get_path( src, dst ).empty();
	}

	// Checks whether the block is in a loop.
	//
	bool routine::is_looping( const basic_block* blk ) const
	{
		for ( auto prev : blk->prev )
			if ( has_path( blk, prev ) )
				return true;
		return false;
	}

	// Explores the paths for the block, reserved for internal use.
	//
	void routine::explore_paths( const basic_block* blk )
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Signal modification.
		//
		signal_cfg_modification();

		// Declare linker.
		//
		auto relink = [ & ] ( const basic_block* src, const basic_block* dst )
		{
			// Insert direct link.
			// src => dst
			//
			auto& src_links = path_cache[ src ];
			auto& fwd_d = src_links[ dst ];
			bool new_f = fwd_d.insert( dst ).second;
			fwd_d.insert( src );

			// Backward propagate.
			// src->prev => dst
			//
			for ( auto& [src2, entry] : path_cache )
			{
				if ( auto it = entry.find( src ); it != entry.end() )
				{
					path_set& ps = it->second;
					auto& fwd = entry[ dst ];
					fwd.insert( ps.begin(), ps.end() );
					fwd.insert( dst );
				}
			}

			// Forward propagate.
			// src => dst->next
			//
			auto& dst_links = path_cache[ dst ];
			for ( auto& [dst2, path] : dst_links )
			{
				auto& fwd = src_links[ dst2 ];
				fwd.insert( path.begin(), path.end() );
				fwd.insert( src );
			}
		};

		// Insert self link.
		//
		path_cache[ blk ][ blk ].insert( blk );

		// Relink each vertex.
		//
		for ( auto next : blk->next )
			relink( blk, next );
		for ( auto prev : blk->prev )
			relink( prev, blk );
	}

	// Flushes the path cache, reserved for internal use.
	//
	void routine::flush_paths()
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Signal modification.
		//
		signal_cfg_modification();

		// Reset to only self links.
		//
		path_cache.clear();
		for_each( [ & ] ( auto blk ) 
		{ 
			path_cache[ blk ][ blk ].insert( blk ); 
		} );

		// Create vertices.
		//
		for_each( [ & ] ( auto blk ) 
		{
			explore_paths( blk );
		} );
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

		// Signal modification.
		//
		signal_cfg_modification();

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
			
			// Create self link.
			//
			path_cache[ block ][ block ].insert( block );
		}

		// Fix links and explore the path.
		//
		if ( src )
		{
			fassert( src->owner == this );
		
			bool new_next = std::find( src->next.begin(), src->next.end(), block ) == src->next.end();
			bool new_prev = inserted || std::find( block->prev.begin(), block->prev.end(), src ) == block->prev.end();

			if ( new_prev ) block->prev.emplace_back( src );
			if ( new_next ) src->next.emplace_back( block );

			if ( new_prev || new_next )
				explore_paths( block );
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

		// Signal modification.
		//
		signal_cfg_modification();

		// Enumerate path_map.
		//
		for ( auto it = path_cache.begin(); it != path_cache.end(); )
		{
			// If entry key references deleted block, erase it and continue.
			//
			if ( it->first == block )
			{
				it = path_cache.erase( it );
				continue;
			}

			// Enumerate std::unordered_map<const basic_block*, path_set>:
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

		// Remove from explored blocks and delete it.
		//
		explored_blocks.erase( block->entry_vip );
		delete block;
	}

	// Gets a list of exits.
	//
	std::vector<const basic_block*> routine::get_exits() const
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Make a vector of all blocks with no next's and return.
		//
		std::vector<const basic_block*> exits;
		for ( auto& [vip, block] : explored_blocks )
			if ( block->next.empty() )
				exits.push_back( block );
		return exits;
	}

	// Gets a list of depth ordered block lists that can be analysed in parallel with 
	// weakened dependencies on previous level.
	//
	std::vector<routine::depth_placement> routine::get_depth_ordered_list( bool fwd ) const
	{
		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Return if already cached.
		//
		auto& cache = depth_ordered_list_cache[ fwd ? 1 : 0 ];
		if ( std::exchange( cache.epoch, cfg_epoch ) == cfg_epoch )
			return cache.list;

		// Allocate visited list.
		//
		path_set visited;
		visited.reserve( num_blocks() );

		// Begin state, if forward from entry, else from exits.
		//
		std::vector<std::pair<size_t, std::vector<const basic_block*>>> state = {};

		if ( fwd )
		{
			if ( entry_point )
				state.push_back( { 0, { entry_point } } );
		}
		else
		{
			if ( auto exits = get_exits(); !exits.empty() )
				state.emplace_back( 0, std::move( exits ) );
		}

		// Hold previous size, start loop.
		//
		size_t previous_counter = 0;
		for ( size_t depth = 1;; depth++ )
		{
			// For each block in previous state:
			//
			size_t counter = state.size();
			for ( size_t p_idx = previous_counter; p_idx != counter; p_idx++ )
			{
				for ( auto& block : backwards( state[ p_idx ].second ) )
				{
					// For each possible source:
					//
					for ( auto& next : ( fwd ? block->next : block->prev ) )
					{
						// Skip if already visited.
						//
						if ( !visited.emplace( next ).second )
							continue;

						// Try to merge into any list.
						//
						size_t n_idx = state.size();
						for ( ; n_idx != counter; n_idx-- )
						{
							auto& stream = state[ n_idx - 1 ];

							// If it will cause circular dependencies within stream, skip.
							//
							auto conflict_it = std::find_if( stream.second.begin(), stream.second.end(), [ & ] ( auto other )
							{
								if ( fwd )
								{
									return std::find( next->prev.begin(), next->prev.end(), other ) != next->prev.end() ||
										   std::find( other->prev.begin(), other->prev.end(), next ) != other->prev.end();
								}
								else
								{
									return std::find( next->next.begin(), next->next.end(), other ) != next->next.end() ||
										   std::find( other->next.begin(), other->next.end(), next ) != other->next.end();
								}
							} );

							if ( conflict_it != stream.second.end() )
								continue;

							// Insert into the list and stop the search.
							//
							stream.second.emplace_back( next );
							break;
						}

						// If we could not insert into any list, create another.
						//
						if ( n_idx == counter )
							state.insert( state.begin() + counter, { depth, { next } } );
					}
				}
			}

			// If none inserted, break.
			//
			if ( counter == state.size() )
				break;
		}

		// Flatten to make it easier to copy, write to cache and return.
		//
		cache.list.clear();
		cache.list.reserve( num_blocks() );

		for ( auto [list, level_dependency] : zip( state, iindices ) )
		{
			for ( auto block : list.second )
			{
				cache.list.push_back( {
						.level_dependency = level_dependency,
						.level_depth = list.first,
						.block = block
				} );
			}
		}

		// Return the result.
		//
		return cache.list;
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
		for ( const auto& [k1, v] : this->path_cache )
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
			copy->path_cache.emplace( copy->get_block( k1->entry_vip ), std::move( map_l2 ) );
		}

		// Fix depth ordered list cache.
		//
		for ( auto& list : copy->depth_ordered_list_cache )
		{
			if ( list.epoch == copy->cfg_epoch )
			{
				for ( auto& entry : list.list )
				{
					entry.block = copy->get_block( entry.block->entry_vip );
				}
			}
		}

		// Return the copy.
		//
		return copy;
	}
};
