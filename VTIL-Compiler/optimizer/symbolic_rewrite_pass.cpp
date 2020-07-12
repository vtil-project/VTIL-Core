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
#include "symbolic_rewrite_pass.hpp"
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t isymbolic_rewrite_pass::pass( basic_block* blk, bool xblock )
	{
		// Determine the temporary sizes in the block.
		//
		std::map<std::pair<uint64_t, uint64_t>, bitcnt_t> temp_sizes;
		for ( auto& ins : blk->stream )
		{
			for ( auto& op : ins.operands )
			{
				if ( op.is_register() && op.reg().is_local() )
				{
					bitcnt_t& sz = temp_sizes[ { op.reg().flags, op.reg().combined_id } ];
					sz = std::max( sz, op.reg().bit_count + op.reg().bit_offset );
				}
			}
		}

		// Create an instrumented symbolic virtual machine and hook execution to exit at 
		// instructions that cannot be executed out-of-order.
		//
		lambda_vm<symbolic_vm> vm;
		vm.hooks.size_register = [ & ] ( const register_desc& reg )
		{
			if ( auto it = temp_sizes.find( { reg.flags, reg.combined_id } );
				      it != temp_sizes.end() )
			{
				// Pick the minimum size from preferred sizes.
				//
				return it->second ? it->second : 64;
			}
			return 64;
		};
		vm.hooks.execute = [ & ] ( const instruction& ins )
		{
			// Halt if branching instruction.
			//
			if ( ins.base->is_branching() )
				return false;

			// Halt if instruction is volatile.
			//
			if ( ins.is_volatile() )
				return false;

			// Halt if stack pointer is reset.
			//
			if ( ins.sp_reset )
				return false;

			// Halt if instruction accesses volatile registers excluding ?UD.
			//
			for ( auto& op : ins.operands )
				if ( op.is_register() && op.reg().is_volatile() && !op.reg().is_undefined() )
					return false;

			// Halt if instruction is accessing to non-restricted memory.
			//
			if ( ins.base->accesses_memory() )
			{
				auto [base, offset] = ins.memory_location();
				if ( !symbolic::pointer::restricted_bases.contains( base ) )
				{
					auto ptr = vm.read_register( base ) + offset;
					for ( auto& [k, v] : vm.memory_state )
						if ( k.can_overlap( ptr ) && !( k - ptr ).has_value() )
							return false;
				}
			}

			// Invoke original handler.
			//
			return vm.symbolic_vm::execute( ins );
		};

		// Allocate a temporary block.
		//
		basic_block temporary_block;
		temporary_block.last_temporary_index = blk->last_temporary_index;
		temporary_block.owner = blk->owner;

		for ( il_const_iterator it = blk->begin(); !it.is_end(); )
		{
			// Execute starting from the instruction.
			//
			auto limit = vm.run( it, true );

			// Create a batch translator and an instruction buffer.
			//
			std::vector<instruction> instruction_buffer;
			batch_translator translator = { &temporary_block };

			// For each register state:
			//
			for ( auto& pair : vm.register_state )
			{
				// If value is unchanged, skip.
				//
				auto k = pair.first; auto v = pair.second.simplify();
				symbolic::expression v0 = symbolic::make_register_ex( k );
				if ( v->equals( v0 ) )
					continue;

				// If register value is not used after this instruction, skip from emitted state.
				//
				if ( !aux::is_used( { std::prev( limit ), k }, false, nullptr ) )
					continue;
				
				// Try minimizing expression size.
				//
				for ( bitcnt_t size : preferred_exp_sizes )
				{
					// Skip if above or equal.
					//
					if ( size >= v.size() ) break;

					// If all bits above [size] are matching with original value, resize.
					//
					if ( ( v >> size ).equals( v0 >> size ) )
					{
						k.bit_count = size;
						v.resize( size );
						break;
					}
				}

				// If partially inherited flags register:
				//
				if ( k.is_flags() && k.bit_count != 64 && preferred_exp_sizes.contains( 1 ) )
				{
					// For each bit:
					//
					for ( int i = 0; i < k.bit_count; i++ )
					{
						// Skip if unchanged.
						//
						auto subexp = __bt( v, i );
						if ( subexp.equals( __bt( v0, i ) ) )
							continue;
						
						// Pack registers and the expression.
						//
						auto sv = symbolic::variable::pack_all( subexp );

						// Buffer a mov instruction to the exact bit.
						//
						register_desc ks = k;
						ks.bit_offset += i;
						ks.bit_count = 1;
						instruction_buffer.push_back( { &ins::mov, { ks, translator << sv } } );
					}
					continue;
				}
				
				// Validate the register output.
				//
				fassert( !k.is_stack_pointer() && !k.is_read_only() );

				// Pack registers and the expression.
				//
				auto final_value = symbolic::variable::pack_all( v.simplify( true ) );

				// Buffer a mov instruction.
				//
				instruction_buffer.push_back( { &ins::mov, { k, translator << final_value } } );
			}

			// For each memory state:
			// -- TODO: Simplify memory state, merge if simplifies, discard if left as is.
			//
			for ( const auto& [k, _v] : vm.memory_state )
			{
				auto v = _v.simplify();
				symbolic::expression v0 = symbolic::make_memory_ex( k, v.size() );

				// If value is unchanged, skip.
				//
				if ( v->equals( v0 ) )
					continue;

				// Try minimizing expression size.
				//
				for ( bitcnt_t size : preferred_exp_sizes )
				{
					// Skip if not byte-aligned.
					//
					if ( size & 7 ) continue;

					// If all bits above [size] are matching with original value, resize.
					//
					if ( ( v >> size ).equals( v0 >> size ) )
					{
						v.resize( size );
						break;
					}
				}

				// Pack registers and the expression.
				//
				v = symbolic::variable::pack_all( v.simplify( true ) );

				// If pointer can be rewritten as $sp + C:
				//
				operand base, offset, value;
				if ( auto displacement = ( k - symbolic::make_register_ex( REG_SP ) ) )
				{
					// Buffer a str $sp, c, value.
					//
					instruction_buffer.push_back(
					{
						&ins::str,
						{ REG_SP, make_imm<int64_t>( *displacement ), translator << v }
					} );
				}
				else
				{
					// Try to extract the offset from the compound expression.
					//
					int64_t offset = 0;
					auto exp = symbolic::variable::pack_all( k.base ).simplify( true );
					if ( !exp->is_constant() )
					{
						using namespace symbolic::directive;

						std::vector<symbol_table_t> results;
						if ( fast_match( &results, A + U, exp ) )
						{
							exp = results.front().translate( A );
							offset = *results.front().translate( U )->get<int64_t>();
						}
						else if ( fast_match( &results, A - U, exp ) )
						{
							exp = results.front().translate( A );
							offset = -*results.front().translate( U )->get<int64_t>();
						}
					}

					// Translate the base address.
					//
					operand base = translator << exp;
					if ( base.is_immediate() )
					{
						operand tmp = temporary_block.tmp( base.bit_count() );
						instruction_buffer.push_back( { &ins::mov, { tmp, base } } );
						base = tmp;
					}

					// Buffer a str <ptr>, 0, value.
					//
					instruction_buffer.push_back(
					{
						&ins::str,
						{ base, make_imm( offset ), translator << v }
					} );
				}
			}

			// Emit entire buffer.
			//
			for ( auto& ins : instruction_buffer )
				temporary_block.push_back( std::move( ins ) );

			// If halting instruction is not at the end of the block, add to temporary block
			// and continue from the next instruction.
			//
			if ( !limit.is_end() )
			{
				temporary_block.stream.emplace_back( *limit );
				it = std::next( limit );
				temporary_block.sp_index = it.is_end() ? blk->sp_index : it->sp_index;
			}
			// Otherwise break from the loop.
			//
			else
			{
				break;
			}

			// Reset virtual machine state.
			//
			vm.reset();
		}

		// Skip rewriting if we produced larger code.
		//
		int64_t opt_count = blk->stream.size() - temporary_block.stream.size();
		if ( opt_count <= 0 )
		{
			if ( !force ) return 0;
			opt_count = 0;
		}

		// Acquire a unique lock and rewrite the stream. Purge simplifier cache since block 
		// iterators are now invalidated making the cache also invalid.
		//
		blk->stream = temporary_block.stream;
		blk->last_temporary_index = temporary_block.last_temporary_index;
		symbolic::purge_simplifier_cache();
		return opt_count;
	}
};