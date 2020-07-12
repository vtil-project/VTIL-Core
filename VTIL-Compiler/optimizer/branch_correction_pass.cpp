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
#include "branch_correction_pass.hpp"
#include <vtil/symex>
#include <algorithm>
#include <future>
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t branch_correction_pass::pass( basic_block* blk, bool xblock )
	{
		// If block is not complete or not cross-block, skip.
		//
		if ( !blk->is_complete() || !xblock )
			return 0;

		size_t cnt = 0;

		// Analyse the branch first locally, next globally.
		//
		cached_tracer local_tracer = {};
		auto lbranch_info = aux::analyze_branch( blk, &local_tracer, {} );
		ctracer.mtx.lock();
		for ( auto& [k, v] : local_tracer.cache )
			ctracer.cache[ k ] = v;
		ctracer.mtx.unlock();
		auto branch_info = aux::analyze_branch( blk, &ctracer, { .cross_block = true, .pack = true, .resolve_opaque = true } );

		// If branching to real, assert single next block.
		//
		auto branch = std::prev( blk->end() );
		if ( branch->base->is_branching_real() )
		{
			fassert( blk->next.size() <= 1 );
		}
		// If branching to virtual instruction:
		//
		else
		{
			fassert( branch->base->is_branching_virt() );
			// For each destination block:
			//
			for ( auto it = blk->next.begin(); it != blk->next.end(); )
			{
				// Check if this destination is plausible or not.
				//
				vip_t target = ( *it )->entry_vip;
				bool plausible = false;
				for ( auto& branch : branch_info.destinations )
					plausible |= ( branch == target ).get<bool>().value_or( true );

				// If it is not:
				//
				if ( !plausible )
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
		}

		// If branch is jmp where it could be jcc:
		//
		if ( branch_info.is_jcc && 
			 lbranch_info.is_jcc && 
			 branch->base == &ins::jmp )
		{
			// Attempts to revive an expression via cache.
			//
			const auto revive_via_cache = [ & ] ( const symbolic::expression& exp, cached_tracer* tr ) -> std::future<operand>
			{
				// If immediate return as is.
				//
				if ( exp.is_constant() )
					return std::async( std::launch::deferred, [ op = operand{ *exp.get<uint64_t>(), exp.size() } ]() { return op; } );

				// If expression is not a register:
				//
				symbolic::variable var_reg;
				if ( !exp.is_variable() || !exp.uid.get<symbolic::variable>().is_register() )
				{
					// Iterate cache entries:
					//
					std::shared_lock _g{ tr->mtx };
					for ( auto& [var, ex] : tr->cache )
					{
						// Skip if memory variable or has invalid iterator.
						//
						if ( var.is_memory() || !var.at.is_valid() )
							continue;

						// If expressions are not identical skip.
						//
						if ( !ex->is_identical( exp ) )
							continue;

						// Set var_reg and break.
						//
						var_reg = var;
						break;
					}
				}
				else
				{
					var_reg = exp.uid.get<symbolic::variable>();
				}

				// Fail if invalid.
				//
				if ( !var_reg.is_valid() )
					return {};

				// Check if alive, if not revive, else return as is.
				//
				if ( aux::is_alive( var_reg, branch, xblock, &ctracer ) )
					return std::async( std::launch::deferred, [ op = operand{ var_reg.reg() } ]() { return op; } );
				else
					return std::async( std::launch::deferred, [ = ]() -> operand { return aux::revive_register( var_reg, branch ); } );
			};

			// Convert [cc] [d1] [d2] in order.
			//
			auto op_cc = revive_via_cache( *lbranch_info.cc, &local_tracer );
			if ( op_cc.valid() )
			{
				bool fail = false;
				std::future<operand> dsts[ 2 ];
				for ( auto [out, blocal, bglobal] : zip( dsts, lbranch_info.destinations, branch_info.destinations ) )
				{
					std::future<operand> op;
					if ( blocal->complexity <= bglobal->complexity )
						op = revive_via_cache( *blocal, &local_tracer );
					else
						op = revive_via_cache( *bglobal, &ctracer );

					if ( !op.valid() )
					{
						fail = true;
						break;
					}
					out = std::move( op );
				}

				// If we converted all succesfully:
				//
				if ( !fail )
				{
					operand cc_op = op_cc.get();
					cc_op.reg().bit_count = 1;

					branch->base = &ins::js;
					branch->operands = {
						cc_op,
						dsts[ 0 ].get(),
						dsts[ 1 ].get()
					};
					cnt++;
				}
			}
			// TODO: Generate exp if we cannot convert.
		}
		// If branch is [j/c* reg] where it could be [j/c* reg] imm:
		//
		if ( branch_info.destinations.size() == 1 &&
			 branch_info.destinations[ 0 ]->is_constant() &&
			 ( branch->base == &ins::jmp || branch->base == &ins::vxcall || branch->base == &ins::vexit ) &&
			 branch->operands[ 0 ].is_register() )
		{

			branch->operands[ 0 ] = { *branch_info.destinations[ 0 ]->get<vip_t>(), 64 };
			cnt++;
		}

		return cnt;
	}
	size_t branch_correction_pass::xpass( routine* rtn )
	{
		// Invoke original method, if any removed:
		//
		if ( size_t cnt = pass_interface<>::xpass( rtn ) )
		{
			// Delete non-referenced blocks entirely.
			//
			bool repeat;
			do
			{
				repeat = false;

				for ( auto it = rtn->explored_blocks.begin(); it != rtn->explored_blocks.end(); )
				{
					if ( it->second->prev.size() == 0 && it->second != rtn->entry_point )
					{
						// For each destination:
						//
						for ( auto& block : it->second->next )
						{
							// Remove the link.
							//
							block->prev.erase( std::remove( block->prev.begin(), block->prev.end(), it->second ), block->prev.end() );
							
							// If no prev link left, repeat logic.
							//
							repeat |= block->prev.empty();
						}

						// Erase block.
						//
						it = rtn->explored_blocks.erase( it );
					}
					else
					{
						++it;
					}
				}
				
			}
			while ( repeat );

			// Flush paths.
			//
			rtn->flush_paths();
			
			// Return counter as is.
			//
			return cnt;
		}
		return 0;
	}
};