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
#include "fast_propagation_pass.hpp"
#include "fast_dead_code_elimination_pass.hpp"
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	size_t fast_reg_propagation_pass::pass( basic_block *blk, bool xblock )
	{
		size_t counter = 0;

		std::unordered_map<register_id, operand> reg_cache;
		for ( auto it = blk->begin(); !it.is_end(); )
		{
			auto& ins = *+it;
			++it;

			// Check register reads and propagate if necessary.
			//
			if ( !ins.is_volatile() )
			{
				for ( auto [op, type] : ins.enum_operands() )
				{
					if ( !op.is_register() )
						continue;

					if ( type >= operand_type::write )
						continue;

					auto& reg = op.reg();
					if ( auto c_it = reg_cache.find( register_id( reg ) ); c_it != reg_cache.end() )
					{
						const auto& new_op = c_it->second;

						// Check for operand validity.
						//
						if ( op.bit_count() != new_op.bit_count() )
							continue;

						if ( type == operand_type::read_reg )
							if ( !new_op.is_register() )
								continue;

						// Replace.
						//
						op = new_op;
						++counter;
					}
				}
			}

			// Do we manipulate a register? If so, adjust or flush caches.
			//
			for (auto [op, type] : ins.enum_operands())
			{
				if (!op.is_register())
					continue;

				if (type >= operand_type::write)
				{
					auto did_write = false;
					const auto reg_id = register_id( op.reg() );

					// Erase entries we can't propagate due to this move.
					//
					for ( auto reg_it = reg_cache.begin(), end = reg_cache.end(); reg_it != end; )
					{
						auto& [id, operand] = *reg_it;

						if ( operand.is_register() && register_id( operand.reg() ) == reg_id )
						{
							reg_it = reg_cache.erase( reg_it );
							end = reg_cache.end();
						}
						else
						{
							++reg_it;
						}
					}

					if ( ins.base == &ins::mov && op.bit_count() == 64 )
					{
						auto to_write = ins.operands [ 1 ];
						if ( !to_write.is_register() || ( !to_write.reg().is_volatile() && !to_write.reg().is_stack_pointer() ) )
						{
							did_write = true;
							reg_cache [ reg_id ] = to_write;
							break;
						}
					}

					reg_cache.erase( reg_id );
					break;
				}
			}
		}

		return counter;
	}

	size_t fast_mem_propagation_pass::pass( basic_block* blk, bool xblock )
	{
		size_t counter = 0;

		// Offset, Mask, Descriptor
		using store_descriptor = std::tuple<uint64_t, uint64_t, register_desc>;

		std::unordered_map<register_id, std::unordered_map<int64_t, std::vector<store_descriptor>>> aligned_mem_cache;
		for ( auto it = blk->begin(); !it.is_end(); )
		{
			auto& ins = *+it;
			++it;

			// If this instruction writes to memory, check for alignment and set cache.
			//
			if ( ins.base->writes_memory() )
			{
				const auto sz = ins.access_size();
				auto [reg, offset] = ins.memory_location();
				const auto offset_mod = ( 8 + ( offset % 8 ) ) % 8;
				const int64_t aligned_offset = offset - offset_mod;

				const auto reg_id = register_id( reg );

				// If this instruction is unaligned and can't be reduced to an aligned store with an offset, flush relevant caches and bail.
				//
				if ( offset_mod * 8 + sz > 64 )
				{
					aligned_mem_cache [ reg_id ][ aligned_offset ].clear();
					aligned_mem_cache [ reg_id ][ aligned_offset + 8 ].clear();
					continue;
				}
				
				// If we are a store, attempt propagation.
				//
				if ( ins.base == &ins::str )
				{

					// Create store mask.
					//
					auto store_mask = math::fill( sz, math::narrow_cast<bitcnt_t>( offset_mod * 8 ) );

					// Do cache lookup. If this mask shadows an existing write, overwrite. Otherwise, add entry to cache.
					//
					auto did_write = false;
					auto& cache_entry = aligned_mem_cache [ reg_id ][ aligned_offset ];
					for ( auto cache_it = cache_entry.begin(), cache_end = cache_entry.end(); cache_it != cache_end; )
					{
						auto& [cache_store_offset, cache_store_mask, cache_ins_reg] = *cache_it;

						// Do we overlap this write?
						//
						if ( ( store_mask & cache_store_mask ) != 0 )
						{
							// Do we *fully* overlap?
							//
							if ( ( ~store_mask & cache_store_mask ) == 0 )
							{
								// Have we already done an update to an existing cache entry?
								//
								if ( did_write )
								{
									// Erase this entry and continue.
									//
									cache_it = cache_entry.erase( cache_it );
									cache_end = cache_entry.end();
									continue;
								}
								else
								{
									// Update the entry with new details.
									//
									did_write = true;
									cache_store_offset = offset_mod;
									cache_store_mask = store_mask;
									cache_ins_reg = blk->tmp( 64 );

									// Emit a move here after incrementing the iterator. If it's not used, DCE will kill it.
									//
									blk->insert( it, { &ins::mov, { cache_ins_reg, ins.operands [ 2 ] } } );
								}
							}
							else
							{
								// Update this mask to reflect changes made with this store.
								//
								cache_store_mask &= ~store_mask;
							}
						}

						// Increment iterator.
						//
						++cache_it;
					}

					// If we haven't done a write, add us to the cache.
					//
					if ( !did_write )
					{
						auto ins_reg = blk->tmp( 64 );
						blk->insert( it, { &ins::mov, { { ins_reg }, ins.operands [ 2 ] } } );
						cache_entry.emplace_back( offset_mod, store_mask, ins_reg );
					}

					// Flush cache for other registers.
					//
					for ( auto& [id, cache] : aligned_mem_cache )
						if ( id != reg_id )
							cache.clear();
				}
				else
				{
					// Otherwise, flush.
					//
					aligned_mem_cache [ reg_id ][ aligned_offset ].clear();

					// Flush cache for other registers.
					//
					for ( auto& [id, cache] : aligned_mem_cache )
						if ( id != reg_id )
							cache.clear();
				}
			}

			// Otherwise, check if we are a load that we have cached. If so, grab cache entry, emit a move from every write, and OR them together at the end. After that, 
			// 
			else if ( ins.base == &ins::ldd && !ins.is_volatile() )
			{
				const auto sz = ins.access_size();
				auto [reg, offset] = ins.memory_location();
				const auto offset_mod = ( 8 + ( offset % 8 ) ) % 8;
				const int64_t aligned_offset = offset - offset_mod;

				// If this instruction is unaligned and can't be reduced to an aligned load with an offset, bail.
				//
				if ( offset_mod * 8 + sz > 64 )
					continue;

				const auto reg_id = register_id( reg );

				uint64_t final_store_mask = 0;

				// Create read mask.
				//
				auto read_mask = math::fill( sz, math::narrow_cast<bitcnt_t>( offset_mod * 8 ) );

				// Do a cache lookup. Find all stores that overlap this load.
				//
				stack_vector<store_descriptor*, 4> overlap_stores;
				auto& cache_entry = aligned_mem_cache [ reg_id ][ aligned_offset ];
				for ( auto& tup : cache_entry )
				{
					auto& [store_offset, store_mask, ins_reg] = tup;

					// Do we partially or fully overlap this write?
					//
					if ( ( read_mask & store_mask ) != 0 )
					{
						// Add to list of overlap stores.
						//
						overlap_stores.push_back( &tup );

						// Update mask.
						//
						final_store_mask |= store_mask;
					}
				}

				// If the store mask does not fully overlap the read mask, bail.
				//
				if ( ( read_mask & ~final_store_mask ) != 0 )
					continue;

				// Set to mov.
				//
				ins.base = &ins::mov;

				// Fast path: If we have one overlapping store, just emit a mov based on register cache.
				//

				if ( overlap_stores.size() == 1 )
				{
					auto& [store_offset, store_mask, ins_reg] = *overlap_stores [ 0 ];

					// If the store mask is equivalent to the read mask, simply emit a mov.
					if ( store_mask == read_mask )
					{
						ins.operands = { ins.operands [ 0 ], { ins_reg } };
					}
					else
					{
						// Otherwise, do bit math.
						auto tmp = blk->tmp( 64 );
						const auto prev_it = std::prev( it );

						blk->insert( prev_it, { &ins::mov, { { tmp }, { ins_reg } } } );
						if ( store_offset > 0 )
							blk->insert( prev_it, { &ins::bshl, { { tmp }, { store_offset * 8, 64 } } } );
						blk->insert( prev_it, { &ins::band, { { tmp }, { store_mask, 64 } } } );

						// Shift by offset.
						//
						if ( offset_mod != 0 )
							blk->insert( prev_it, { &ins::bshr, { { tmp }, { offset_mod * 8, 64 } } } );

						// Set operand.
						//
						ins.operands = { ins.operands [ 0 ], { tmp } };
					}
				}
				else
				{
					// Create a temporary that we will use to store the final result.
					//
					auto final_tmp = blk->tmp( 64 );
					const auto prev_it = std::prev( it );

					// For every overlapping store, create a temporary, shift by offset, and with mask, and add to final temporary.
					//
					auto first = true;
					for ( auto* store : overlap_stores )
					{
						auto& [store_offset, store_mask, ins_reg] = *store;

						// If the store mask is full, just emit a mov and break out.
						//
						if ( store_mask == ~0ULL )
						{
							blk->insert( prev_it, { &ins::mov, { { final_tmp }, { ins_reg } } } );
							break;
						}
						else
						{
							if ( first )
								blk->insert( prev_it, { &ins::mov, { { final_tmp }, { 0ULL, 64 } } } );

							auto tmp = blk->tmp( 64 );
							blk->insert( prev_it, { &ins::mov, { { tmp }, { ins_reg } } } );
							if ( store_offset > 0 )
								blk->insert( prev_it, { &ins::bshl, { { tmp }, { store_offset * 8, 64 } } } );
							blk->insert( prev_it, { &ins::band, { { tmp }, { store_mask, 64 } } } );
							blk->insert( prev_it, { &ins::bor, { { final_tmp }, { tmp } } } );
						}
					}

					// Shift by offset.
					//
					if ( offset_mod != 0 )
						blk->insert( prev_it, { &ins::bshr, { { final_tmp }, { offset_mod * 8, 64 } } } );

					ins.operands = { ins.operands [ 0 ], { final_tmp } };
				}

				// Increment counter.
				//
				++counter;
			}

			// Do we manipulate a register? If so, adjust or flush caches.
			//
			for ( auto [op, type] : ins.enum_operands() )
			{
				if ( !op.is_register() )
					continue;

				if ( type >= operand_type::write )
				{
					const auto reg_id = register_id( op.reg() );
					const auto to_write = ins.operands [ 1 ];
					if ( *ins.base == ins::mov && op.bit_count() == 64 && to_write.is_register() )
					{
						aligned_mem_cache [ reg_id ] = aligned_mem_cache [ register_id( to_write.reg() ) ];
					}
					else
					{
						aligned_mem_cache [ reg_id ].clear();
					}

					break;
				}
			}
		}

		return counter;
	}
}