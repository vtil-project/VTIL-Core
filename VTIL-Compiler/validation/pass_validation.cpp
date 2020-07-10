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
#include "pass_validation.hpp"

namespace vtil::optimizer::validation
{
	// Helper routine used to compare routine behaviour against expected behaviour.
	//
	bool verify_symbolic( const routine* rtn, const std::vector<uint64_t>& parameters, const std::vector<observable_action>& action_log )
	{
		auto action_it = action_log.begin();
		auto action_end = action_log.end();

		// Create the symbolic virtual machine.
		//
		lambda_vm<symbolic_vm> vm = {};

		// Write default register state.
		//
		for ( auto& [k, v] : default_register_state )
			vm.write_register( k, v );

		// Write the parameters.
		//
		const call_convention& call_conv = rtn->routine_convention;
		auto rit = call_conv.param_registers.begin();
		for ( auto [value, id] : zip( parameters, iindices() ) )
		{
			// If we did not reach the end of registers yet:
			//
			if ( rit != call_conv.param_registers.end() )
			{
				vm.write_register( *rit++, value );
			}
			// Otherwise, write into the stack.
			//
			else
			{
				// Calculate the surplus index.
				//
				size_t idx = id - call_conv.param_registers.size();

				// Calculate the address on stack and write into it.
				//
				vm.write_memory(
					vm.read_register( REG_SP ) + ( idx * 8 ) + call_conv.shadow_space + 8,
					value
				);
			}
		}

		// Write the return address, any random will work so let's 
		// use a pointer off of our own stack.
		//
		const uint64_t return_address = ( uint64_t ) &vm;
		vm.write_memory( vm.read_register( REG_SP ), return_address );

		// Instrument the virtual execution to verify actions:
		//
		bool success = true;
		vm.hooks.execute = [ & ] ( const instruction& ins )
		{
			// If failed already, exit.
			//
			if ( !success ) return false;

			// If hint is hit, skip.
			//
			if ( *ins.base == ins::vpinr ) return true;
			if ( *ins.base == ins::vpinw ) return true;

			// If a virtual branch is hit, exit the virtual machine so we can handle it. 
			//
			if ( ins.base->is_branching_virt() )
				return false;

			// If branching to real location:
			//
			if ( ins.base->is_branching_real() )
			{
				// If external call:
				//
				if ( ins.base == &ins::vxcall )
				{
					// If was not expected, fail and exit the virtual machine.
					//
					if ( action_it == action_end || !std::get_if<external_call>( &*action_it ) )
					{
						logger::warning( "Unexpected call." );
						success = false;
						return false;
					}

					// Pop it off the stack.
					//
					const external_call& call = std::get<external_call>( *action_it );
					++action_it;

					// Validate target.
					//
					symbolic::expression target_call = ins.operands[ 0 ].is_immediate()
						? ins.operands[ 0 ].imm().u64
						: vm.read_register( ins.operands[ 0 ].reg() );
					if ( target_call.value.get() != call.address )
					{
						logger::warning( "Unexpected callee, expected 0x%llx, got [%s].", call.address, target_call );
						success = false;
						return false;
					}

					// Validate parameters.
					//
					const call_convention& call_conv = rtn->get_cconv( ins.vip );
					auto it = call_conv.param_registers.begin();
					for ( auto [value, id] : zip( call.parameters, iindices() ) )
					{
						symbolic::expression exp;

						// If we did not reach the end of registers yet:
						//
						if ( it != call_conv.param_registers.end() )
						{
							// Read from the register and increment iterator.
							//
							exp = vm.read_register( *it );
							it++;
						}
						else
						{
							// Calculate the surplus index.
							//
							size_t idx = id - call_conv.param_registers.size();

							// Calculate the address on stack and read from it.
							//
							exp = vm.read_memory( vm.read_register( REG_SP ) + ( idx * 8 ) + call_conv.shadow_space + 8, 8 );
						}

						// Fail if value does not match.
						//
						if ( exp.value.get() != value )
						{
							logger::warning( "Parameter %d does not match, expected 0x%llx, got [%s].", id, value, exp );
							success = false;
							return false;
						}
					}

					// Write the simulated return value.
					//
					for ( auto [value, target] : zip( call.fake_result, call_conv.retval_registers ) )
						vm.write_register( target, value );
				}
				// If we're exiting the virtual machine:
				//
				else if ( ins.base == &ins::vexit )
				{
					// If was not expected, fail and exit the virtual machine.
					//
					if ( action_it == action_end || !std::get_if<vm_exit>( &*action_it ) )
					{
						logger::warning( "Unexpected exit." );
						success = false;
						return false;
					}

					// Pop it off the stack.
					//
					vm_exit exit = std::get<vm_exit>( *action_it );
					++action_it;

					// Validate return address.
					//
					symbolic::expression sreturn_address = ins.operands[ 0 ].is_immediate()
						? ins.operands[ 0 ].imm().u64
						: vm.read_register( ins.operands[ 0 ].reg() );
					if ( sreturn_address.value.get() != return_address )
					{
						logger::warning( "Unexpected return address, expected 0x%llx, got [%s].", return_address, sreturn_address );
						success = false;
						return false;
					}

					// Validate the register state / return value.
					//
					for ( auto& [reg, value] : exit.register_state )
					{
						symbolic::expression exp = vm.read_register( reg );
						if ( exp.value.get() != value )
						{
							logger::warning( "Return state %s does not match, expected 0x%llx, got [%s].", reg, value, exp );
							success = false;
							return false;
						}
					}
				}
				return true;
			}

			// If none matches, redirect to original handler.
			//
			return vm.symbolic_vm::execute( ins );
		};

		vm.hooks.read_memory = [ & ] ( const symbolic::expression& pointer, size_t sz )
		{
			symbolic::expression ptr = pointer.simplify();

			// If action log has a matching read memory on top of the stack:
			//
			if ( action_it != action_end && std::get_if<memory_read>( &*action_it ) )
			{
				auto& mem = std::get<memory_read>( *action_it );
				if ( ptr.value.get() == mem.address )
				{
					// Write fake value to the state and pop the stack.
					//
					symbolic::expression value = { mem.fake_value, mem.size };
					vm.symbolic_vm::write_memory( ptr, value );
					++action_it;
				}
			}

			return vm.symbolic_vm::read_memory( ptr, sz );
		};

		vm.hooks.write_memory = [ & ] ( const symbolic::expression& pointer, symbolic::expression exp )
		{
			// If action log has a matching write memory on top of the stack:
			//
			if ( action_it != action_end && std::get_if<memory_write>( &*action_it ) )
			{
				auto& mem = std::get<memory_write>( *action_it );
				if ( pointer.value.get() == mem.address )
				{
					// Pop the stack and validate the value.
					//
					if ( exp.value.get() != mem.value )
					{
						logger::warning( "Unexpected memory write into 0x%llx, expected 0x%llx, got [%s].", mem.address, mem.value, exp );
						success = false;
					}
					++action_it;
				}
			}
			return vm.symbolic_vm::write_memory( pointer, exp );
		};


		// Begin from the entry point:
		//
		il_const_iterator it = rtn->entry_point->begin();
		while ( true )
		{
			// Run until it VM exits.
			//
			auto lim = vm.run( it, true );

			// If failed, return.
			//
			if ( !success ) return false;

			// If we've reached the end of the virtual machine:
			//
			if ( lim.is_end() )
			{
				// If we have a single continue destination (VXCALL), fix iterator and the stack, continue.
				//
				size_t num_continue_dst = lim.container->next.size();
				if ( num_continue_dst == 1 )
				{
					it = lim.container->next[ 0 ]->begin();
					vm.write_register( REG_SP, vm.read_register( REG_SP ) + lim.container->sp_offset );
					continue;
				}
				// If we've reached the end of the routine (VEXIT), signal success if all actions are complete, or fail.
				//
				else if ( num_continue_dst == 0 )
				{
					return action_it == action_end;
				}
				unreachable();
			}

			// If unhandled instruction is branching into virtual location:
			//
			if ( lim->base->is_branching_virt() )
			{
				// Determine the destination.
				//
				operand dst = {};
				if ( lim->base == &ins::js )
					dst = *vm.read_register( lim->operands[ 0 ].reg() ).get<bool>() ? lim->operands[ 1 ] : lim->operands[ 2 ];
				else if ( lim->base == &ins::jmp )
					dst = lim->operands[ 0 ];

				// If operand is an immediate, use as is:
				//
				auto eit = rtn->explored_blocks.end();
				if ( dst.is_immediate() )
					eit = rtn->explored_blocks.find( dst.imm().u64 );
				// Otherwise read VM context.
				//
				else if ( auto jmp_dst = vm.read_register( dst.reg() ).get() )
					eit = rtn->explored_blocks.find( *jmp_dst );

				// If no valid destination, fail.
				//
				if ( eit == rtn->explored_blocks.end() )
				{
					logger::warning( "Invalid virtual jump." );
					return false;
				}

				// Fix iterator and the stack, continue.
				//
				it = eit->second->begin();
				vm.write_register( REG_SP, vm.read_register( REG_SP ) + lim.container->sp_offset );
				continue;
			}

			logger::warning( "Failing execution at: %s\n", lim->to_string() );
			return false;
		}

		// Purge simplifier cache.
		//
		symbolic::purge_simplifier_cache();
	}
};
