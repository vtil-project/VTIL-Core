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
#include "symbolic_rewrite_pass.hpp"
#include "../common/auxiliaries.hpp"

namespace vtil::optimizer
{
	// Implement the pass.
	//
	size_t symbolic_rewrite_pass::pass( basic_block* blk, bool xblock )
	{
		// Acquire shared mutex and create cached tracer.
		//
		std::shared_lock lock{ mtx };
		cached_tracer ctracer = {};

		// Create an instrumented symbolic virtual machine and hook execution to exit at 
		// instructions that cannot be executed out-of-order.
		//
		lambda_vm<symbolic_vm> vm;
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

			// Halt if instruction writes to non [$sp + C] memory.
			//
			if ( ins.base->writes_memory() )
			{
				auto [base, _] = ins.memory_location();
				if ( !base.is_stack_pointer() && !( vm.read_register( base ) - symbolic::make_register_ex( REG_SP ) ).is_constant() )
					return false;
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
			// Reset virtual machine state.
			//
			vm.reset();

			// Execute starting from the instruction.
			//
			auto limit = vm.run( it, true );

			// Create a batch translator and an instruction buffer.
			//
			std::vector<instruction> instruction_buffer;
			batch_translator translator = { &temporary_block };

			// For each register state:
			//
			for ( auto [k, v] : vm.register_state )
			{
				// If register value is not used after this instruction, skip from emitted state.
				//
				if ( !aux::is_used( { std::prev( limit ), k }, xblock, &ctracer ) )
					continue;

				// Translate into an operand, if unchanged skip.
				//
				operand op = translator << v.simplify( true );
				if ( operand{ k } == op )
					continue;

				// Buffer a mov instruction.
				//
				instruction_buffer.push_back( { &ins::mov,{ k, op } } );
			}

			// For each memory state:
			//
			for ( auto [k, v] : vm.memory_state )
			{
				// If value is unchanged, skip.
				//
				if ( v.equals( symbolic::make_memory_ex( k, v.size() ) ) )
					continue;

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
						{ REG_SP, make_imm<int64_t>( *displacement ), translator << v.simplify( true ) }
					} );
				}
				else
				{
					// Buffer a str <ptr>, 0, value.
					//
					instruction_buffer.push_back(
					{
						&ins::str,
						{ translator << k.base, make_imm<int64_t>( 0 ), translator << v.simplify( true ) }
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
		}

		// Skip rewriting if we produced larger code.
		//
		int64_t opt_count = blk->stream.size() - temporary_block.stream.size();
		if ( opt_count <= 0 )
			return 0;

		// Acquire a unique lock and rewrite the stream. Purge simplifier cache since block 
		// iterators are now invalidated making the cache also invalid.
		//
		lock.unlock();
		std::unique_lock{ mtx };
		blk->stream = temporary_block.stream;
		blk->last_temporary_index = temporary_block.last_temporary_index;
		symbolic::purge_simplifier_cache();
		return opt_count;
	}
};