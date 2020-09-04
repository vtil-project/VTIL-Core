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
#include <mutex>
#include <vector>
#include <unordered_map>
#include <vtil/symex>
#include <vtil/common>
#include "preliminary_register_elimination.hpp"

namespace vtil::optimizer
{
	size_t preliminary_register_elimination::pass( basic_block* oblk, bool xblock )
	{
		size_t cnt = 0;

		// Get current block and acquire shared lock over generic mutex.
		//
		analysis::symbolic_analysis& sblk = oblk->context;
		std::shared_lock lock{ oblk->generic_mutex };

		// For each segment:
		//
		std::vector<std::pair<symbolic::context::segmented_value&, uint64_t>> discard_queue;
		for ( auto it = sblk.segments.begin(); it != sblk.segments.end(); ++it )
		{
			// For each register:
			//
			for ( auto& [reg, ctx] : it->register_state )
			{
				// Skip if stack pointer and volatile registers.
				//
				if ( reg.flags & ( register_stack_pointer | register_volatile ) )
					continue;

				// Create a visit list and define the recursive alive-check.
				//
				std::unordered_map<il_const_iterator, uint64_t> visit_list;
				auto get_used_mask = [ & ]( auto&& self,
											const analysis::symbolic_analysis& blk,
											std::list<analysis::symbolic_segment>::const_iterator it,
											const register_desc::weak_id& id ) -> uint64_t
				{
					// If at the end:
					//
					if ( it == blk.end() )
					{
						// If local register, declare dead.
						//
						if ( id.flags & register_local )
							return 0;

						// Update masks based on what the branch operation does.
						//
						uint64_t rmask = 0;
						uint64_t vmask = math::fill( 64 );
						symbolic::variable var = { register_desc{ id, 64, 0 } };
						if ( auto access = var.accessed_by( std::prev( blk.begin()->segment_begin.block->end() ) ) )
						{
							if ( access.read )
								rmask |= math::fill( access.bit_count, access.bit_offset ) & vmask;
							if ( access.write )
								vmask &= ~math::fill( access.bit_count, access.bit_offset );
						}

						// If value is dead return.
						//
						if ( !vmask )
							return rmask;

						// Continue onto each segment.
						//
						for ( auto& next : blk.segments.front().segment_begin.block->next )
						{
							// Get a reference to the block's symbolic analysis.
							//
							const analysis::symbolic_analysis& nblk = next->context;

							// If not current block and not previously visited, acquire shared lock.
							//
							std::shared_lock lock2{ next->generic_mutex, std::defer_lock };
							if ( next != oblk )
							{
								if ( auto it = visit_list.find( nblk.segments.front().segment_begin ); it != visit_list.end() )
								{
									rmask |= it->second & vmask;
									continue;
								}
								else
								{
									lock2.lock();
								}
							}

							// Recurse, or with the mask.
							//
							rmask |= self( self, nblk, nblk.segments.begin(), id ) & vmask;
						}
						return rmask;
					}

					// Check visit cache, return if already inserted.
					//
					auto [vit, inserted] = visit_list.emplace( it->segment_begin, 0ull );
					uint64_t vmask = math::fill( 64 );
					uint64_t& rmask = vit->second;
					if ( !inserted )
						return rmask;

					// Iterate until last segment:
					//
					for ( ; it != blk.segments.end(); ++it )
					{
						// If read from, add to read mask.
						//
						auto rit = it->register_references.find( id );
						if ( rit != it->register_references.end() )
							rmask |= rit->second & vmask;

						// If written to, remove from vmask.
						//
						auto wit = it->register_state.value_map.find( id );
						if ( wit != it->register_state.value_map.end() )
						{
							math::bit_enum( wit->second.bitmap, [ &, vmask = std::ref( vmask ) ]( bitcnt_t n )
							{
								vmask &= ~math::fill( wit->second.linear_store[ n ].size(), n );
							} );
						}

						// If value is dead return.
						//
						if ( !vmask )
							return rmask;

						// Apply same heuristic for suffix:
						//
						bitcnt_t msb = math::msb( vmask ) - 1;
						bitcnt_t lsb = math::lsb( vmask ) - 1;
						symbolic::variable var = { register_desc{ id, msb - lsb + 1, lsb } };
						for ( auto& sfx : it->suffix )
						{
							if ( auto access = var.accessed_by( sfx ) )
							{
								if ( access.read )
									rmask |= math::fill( access.bit_count, access.bit_offset ) & vmask;
								if ( access.write )
									vmask &= ~math::fill( access.bit_count, access.bit_offset );
							}
						}
					}

					// If value is dead return.
					//
					if ( !vmask )
						return rmask;

					// Invoke propagation.
					//
					rmask |= vmask & self( self, blk, blk.segments.end(), id );
					return rmask;
				};
				uint64_t read_mask = get_used_mask( get_used_mask, sblk, std::next( it ), reg );

				// Create the mask for the existing value.
				//
				uint64_t value_mask = 0;
				symbolic::context::segmented_value& vctx = ctx;
				math::bit_enum( ctx.bitmap, [ & ]( bitcnt_t n )
				{
					// If value can be atomically discarded (deleted entirely), do so.
					//
					if ( !( math::fill( vctx.linear_store[ n ].size(), n ) & read_mask ) )
					{
						math::bit_reset( vctx.bitmap, n );
						vctx.linear_store[ n ] = nullptr;
						cnt++;
					}
					// Otherwise, or with value mask.
					//
					else
					{
						value_mask |= math::fill( ctx.linear_store[ n ].size(), n );
					}
				} );

				// If there are still parts that should be discarded, queue for unique stage.
				//
				if( auto discard_mask = value_mask & ~read_mask )
					discard_queue.emplace_back( vctx, discard_mask );
			}
		}

		// Upgrade to unique lock.
		//
		lock.unlock();
		std::unique_lock ulock{ oblk->generic_mutex, std::defer_lock };
		while ( !ulock.try_lock() )
			sleep_for( 0.1ms );

		// For each value in discard queue:
		//
		for ( auto& pair : discard_queue )
		{
			// Until mask is depleted:
			//
			math::bit_enum( pair.first.bitmap, [ & ] ( bitcnt_t n )
			{
				uint64_t value_mask = math::fill( pair.first.linear_store[ n ].size() );
				if ( !( value_mask & ( pair.second >> n ) ) )
					return;

				// Reset the bit and steal the value.
				//
				symbolic::expression::reference value = std::move( pair.first.linear_store[ n ] );
				math::bit_reset( pair.first.bitmap, n );

				// Calculate the preserved region.
				//
				uint64_t preserve = value_mask & ~( pair.second >> n );

				// Bitwise rewrite.
				//
				while ( true )
				{
					// Calculate the next region's offset, break if none left.
					//
					bitcnt_t offset = math::lsb( preserve );
					if ( !offset ) break;
					offset--;

					// Calculate the size.
					//
					bitcnt_t size = 0;
					while ( math::bit_test( preserve, offset + ++size ) );

					// Reset the region in preserve mask, write the value.
					//
					preserve &= ~math::fill( size, offset );
					pair.first.linear_store[ offset + n ] = ( value >> offset ).resize( size );
					math::bit_set( pair.first.bitmap, offset + n );
				}
			} );
			cnt++;
		}

		// Delete register states for completely zero'd out registers.
		//
		for ( auto it = sblk.segments.begin(); it != sblk.segments.end(); ++it )
		{
			for ( auto kit = it->register_state.value_map.begin(); kit != it->register_state.value_map.end(); )
			{
				if ( !kit->second.bitmap )
					kit = it->register_state.value_map.erase( kit );
				else
					++kit;
			}
		}
		return cnt;
	}
};