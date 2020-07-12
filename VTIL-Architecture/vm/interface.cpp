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
#include "interface.hpp"
#include "../symex/variable.hpp"

namespace vtil
{
	// Runs the given instruction, returns whether it was successful.
	//
	bool vm_interface::execute( const instruction& ins )
	{
		// Declare a helper to convert operands of current instruction into expressions.
		//
		auto cvt_operand = [ & ] ( int i ) -> symbolic::expression::reference
		{
			const operand& op = ins.operands[ i ];

			// If operand is a register:
			//
			if ( op.is_register() )
			{
				// Trace the source register.
				//
				symbolic::expression::reference result = read_register( op.reg() );

				// If stack pointer, add the current virtual offset.
				//
				if ( op.reg().is_stack_pointer() )
					result = result + ins.sp_offset;

				// Return the result.
				//
				return result;
			}
			// If it is an immediate, convert into constant expression and return.
			//
			else
			{
				fassert( op.is_immediate() );
				return { op.imm().i64, op.imm().bit_count };
			}
		};

		// If MOV/MOVSX:
		//
		if ( bool cast_signed = ins.base == &ins::movsx;
			 ins.base == &ins::mov || cast_signed )
		{
			// Convert source operand, resize according to the destination size and
			// signed-ness of the instruction and write the read value to the register.
			//
			write_register(
				ins.operands[ 0 ].reg(),
				cvt_operand( 1 )->resize( ins.operands[ 0 ].bit_count(), cast_signed )
			);
			return true;
		}
		// If LDD:
		//
		else if ( ins.base == &ins::ldd )
		{
			// Query base pointer without using the wrapper to skip SP adjustment and 
			// add offset. Read the value and resize to written size.
			//
			auto [base, offset] = ins.memory_location();
			auto exp = read_memory(
				read_register( base ) + offset,
				ins.operands[ 0 ].size()
			);

			// Write the read value to the register.
			//
			write_register(
				ins.operands[ 0 ].reg(),
				std::move( exp )
			);
			return true;
		}
		// If STR:
		//
		else if ( ins.base == &ins::str )
		{
			// Read the source operand and byte-align.
			//
			auto src = cvt_operand( 2 );
			src.resize( ( src->size() + 7 ) & ~7 );

			// Query base pointer without using the wrapper to skip SP adjustment and 
			// add offset. Write the source to the pointer.
			//
			auto [base, offset] = ins.memory_location();
			write_memory( read_register( base ) + offset, std::move( src ) );
			return true;
		}
		// If any symbolic operator:
		//
		else if ( ins.base->symbolic_operator != math::operator_id::invalid )
		{
			// Fetch operator id and allocate result expression.
			//
			math::operator_id op_id = ins.base->symbolic_operator;
			symbolic::expression result;

			// If [X = F(X)]:
			//
			if ( ins.base->operand_count() == 1 )
			{
				result = { op_id, cvt_operand( 0 ) };
			}
			// If [X = F(X, Y)]:
			//
			else if ( ins.base->operand_count() == 2 )
			{
				result = { cvt_operand( 0 ), op_id, cvt_operand( 1 ) };
			}
			// If [X = F(Y, Z)]:
			//
			else if ( ins.base->operand_count() == 3 && ins.base->operand_types[ 0 ] == operand_type::write )
			{
				result = { cvt_operand( 1 ), op_id, cvt_operand( 2 ) };
			}
			// If [X = F(Y:X, Z)]:
			//
			else if ( ins.base->operand_count() == 3 )
			{
				// If high bits are zero:
				//
				auto op1_high = cvt_operand( 1 );
				if ( ( op1_high == 0 ).get().value_or( false ) )
				{
					auto op1 = cvt_operand( 0 );
					result = { op1, op_id, cvt_operand( 2 ) };
				}
				// If high bits are set, but the operation bit-count is equal to or less than 64 bits.
				//
				else if ( ( ins.operands[ 0 ].size() + ins.operands[ 1 ].size() ) <= 8 )
				{
					auto op1_low = cvt_operand( 0 );
					auto op1 = op1_low | ( op1_high->resize( op1_high->size() + op1_low->size() ) << op1_low->size() );
					result = { op1, op_id, cvt_operand( 2 ) };
				}
				// If operation is 65 bits or bigger:
				// TODO: Implement later on.
				//
				else
				{
					return false;
				}
			}

			// Write the result to the destination register.
			//
			write_register( ins.operands[ 0 ].reg(), std::move( result ) );

			// Operand 0 should always be the result for this class.
			//
			fassert( ins.base->operand_types[ 0 ] >= operand_type::write );
			return true;
		}
		// If NOP:
		//
		else if ( ins.base == &ins::nop )
		{
			// No operation.
			//
			return true;
		}

		// Unknown behaviour, fail.
		//
		return false;
	}

	// Given an iterator from a basic block, executes every instruction until the end of the block 
	// is reached. If an unknown instruction is hit, breaks out of the loop if specified so, otherwise
	// ignores it setting the affected registers and memory to undefined values.
	//
	il_const_iterator vm_interface::run( il_const_iterator it, bool exit_on_ud )
	{
		// Until the iterator points at the end of the block:
		//
		for ( ; !it.is_end(); it++ )
		{
			// If we could not virtualize the instruction:
			//
			if ( !execute( *it ) )
			{
				// Break out of the loop if specified so.
				//
				if ( exit_on_ud )
					break;

				// Make each register operand we write to undefined.
				//
				for ( int i = 0; i < it->base->operand_count(); i++ )
				{
					if ( it->base->operand_types[ i ] >= operand_type::write )
					{
						write_register(
							it->operands[ i ].reg(),
							symbolic::make_undefined_ex( it->operands[ i ].reg().bit_count )
						);
					}
				}

				// If instruction writes to memory, mark the region pointed at undefined.
				//
				if ( it->base->writes_memory() )
				{
					auto [base, offset] = it->memory_location();
					write_memory(
						read_register( base ) + offset,
						symbolic::make_undefined_ex( it->access_size() ? it->access_size() : 64 )
					);
				}
			}
		}
		return it;
	}
};