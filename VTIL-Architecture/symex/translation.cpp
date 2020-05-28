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
#include "translation.hpp"
#include <array>

namespace vtil
{
	// Fills a lookup table used to map math::operator_id -> const instruction_desc*
	//
	static const auto lookup_table = [ ] ()
	{
		std::array<const instruction_desc*, ( size_t ) math::operator_id::max> tbl;
		tbl.fill( nullptr );
		for ( auto& x : instruction_list )
			if ( x.symbolic_operator != math::operator_id::invalid )
				tbl[ ( size_t ) x.symbolic_operator ] = &x;
		return tbl;
	}( );
	static const instruction_desc* map_operator( math::operator_id op )
	{
		fassert( lookup_table.size() > ( size_t ) op );
		const instruction_desc* desc = lookup_table[ ( size_t ) op ];
		fassert( desc );
		return desc;
	}

	// Translates the given symbolic expression into instruction equivalents.
	//
	operand translate_expression( const symbolic::expression& exp, basic_block* block, const std::function<operand( const symbolic::expression&, basic_block* )>& proxy )
	{
		// Declare a helper to force an operand into register form.
		//
		const auto force_clobber_register = [ & ] ( operand& op )
		{
			if ( !op.is_register() || !op.reg().is_local() )
			{
				operand tmp = block->tmp( bitcnt_t( op.size() * 8 ) );
				block->mov( tmp, op );
				op = tmp;
			}
		};

		// If no proxy given, use self.
		//
		const auto cvt = [ & ] ( const symbolic::expression& exp )
		{
			if ( proxy )
				return proxy( exp, block );
			else
				return translate_expression( exp, block );
		};

		// Switch operators:
		//
		switch ( auto op = exp.op )
		{
			case math::operator_id::invalid:
			{
				// If constant, simply convert into operand type.
				//
				if ( exp.is_constant() )
				{
					return { *exp.get(), exp.size() };
				}

				// Assert validity and get the variable.
				//
				fassert( exp.is_variable() );
				auto& var = exp.uid.get<symbolic::variable>();

				// If memory, emit LDD into temporary.
				//
				if ( var.is_memory() )
				{
					// If simple stack access:
					//
					if( auto displacement = ( var.mem().base - symbolic::make_register_ex( REG_SP ) ) )
					{
						operand tmp = block->tmp( exp.size() );
						block->ldd( tmp, REG_SP, *displacement );
						return tmp;
					}
					else
					{
						operand tmp = block->tmp( exp.size() );
						block->ldd( tmp, cvt( var.mem().decay() ), 0 );
						return tmp;
					}
				}
				// If register:
				//
				else if ( var.is_register() )
				{
					// Resize the register descriptor to the expression size.
					//
					register_desc reg = var.reg();
					fassert( reg.bit_count >= exp.size() );
					reg.bit_count = exp.size();

					// If stack pointer, remove the current offset:
					//
					if ( reg.is_stack_pointer() && block->sp_offset != 0 )
					{
						operand tmp = block->tmp( reg.bit_count );
						block->mov( tmp, reg )
							 ->sub( tmp, block->sp_offset );
						return tmp;
					}
					return { reg };
				}
				unreachable();
			}
			case math::operator_id::ucast:
			{
				// Emit move into temporary (which is zero-extending by default) and return.
				//
				operand tmp = block->tmp( *exp.rhs->get<bitcnt_t>() );
				block->mov( tmp, cvt( *exp.lhs ) );
				return tmp;
			}
			case math::operator_id::cast:
			{
				// Emit move into temporary by sign-extension.
				//
				operand tmp = block->tmp( *exp.rhs->get<bitcnt_t>() );
				block->movsx( tmp, cvt( *exp.lhs ) );
				return tmp;
			}
			case math::operator_id::bit_test:
			{
				if ( auto offset = exp.rhs->get() )
				{
					// Resolve tested expression into operand and address by-bit.
					//
					operand res = cvt( *exp.lhs );
					force_clobber_register( res );
					res.reg().bit_offset += *offset;
					res.reg().bit_count = 1;
					return res;
				}
				else
				{
					// Translate the shifted version and address first bit.
					//
					operand res = cvt( exp.lhs >> exp.rhs );
					force_clobber_register( res );
					res.reg().bit_count = 1;
					return res;
				}
			}
			case math::operator_id::negate:
			case math::operator_id::bitwise_not:
			{
				// Translate the right hand side into a register.
				//
				operand tmp = cvt( *exp.rhs );
				force_clobber_register( tmp );

				// Push [<INS> Reg1] and return Reg1.
				//
				block->push_back( { map_operator( op ), { tmp } } );
				return tmp;
			}
			case math::operator_id::popcnt:
			{
				// Translate the right hand side into a register.
				//
				operand tmp = cvt( *exp.rhs );
				force_clobber_register( tmp );

				// Push [<INS> Reg1] and return Reg1.
				//
				block->push_back( { map_operator( op ), { tmp } } );

				// Validate size and return resized to 8 bits.
				//
				fassert( tmp.reg().bit_count >= 8 );
				tmp.reg().bit_count = 8;
				return tmp;
			}
			case math::operator_id::bitwise_and:
			case math::operator_id::bitwise_or:
			case math::operator_id::bitwise_xor:
			case math::operator_id::shift_right:
			case math::operator_id::shift_left:
			case math::operator_id::rotate_right:
			case math::operator_id::rotate_left:
			case math::operator_id::add:
			case math::operator_id::subtract:
			case math::operator_id::multiply:
			case math::operator_id::multiply_high:
			case math::operator_id::umultiply:
			case math::operator_id::umultiply_high:
			{
				// Translate the both sides.
				//
				operand lhs = cvt( *exp.lhs );
				operand rhs = cvt( *exp.rhs );

				// If left hand side is not a register, and operator is commutative, switch sides.
				// Force left hand side into a register.
				//
				if ( !lhs.is_register() && math::descriptor_of( op )->is_commutative )
					std::swap( lhs, rhs );

				// Push [<INS> Lhs Rhs] and return Lhs.
				//
				force_clobber_register( lhs );
				block->push_back( { map_operator( op ), { lhs, rhs } } );
				return lhs;
			}
			case math::operator_id::value_if:
			{
				// If Lhs is a register:
				//
				if ( operand lhs = cvt( *exp.lhs ); lhs.is_register() )
				{
					// Resize Lhs to a boolean.
					//
					lhs.reg().bit_count = 1;

					// Allocate temporary.
					//
					operand tmp = block->tmp( exp.rhs->size() );

					// Push [<INS> Tmp Lhs Rhs] and return Tmp.
					//
					block->push_back( { map_operator( op ), { tmp, lhs, cvt( *exp.rhs ) } } );
					return tmp;
				}
				// If Lhs was [true], return Rhs:
				//
				else if( lhs.imm().u64 & 1 )
				{
					return cvt( *exp.rhs );
				}
				// Otherwise return 0.
				//
				else
				{
					return { 0, exp.rhs->size() };
				}
			}
			case math::operator_id::divide:
			case math::operator_id::remainder:
			case math::operator_id::udivide:
			case math::operator_id::uremainder:
			{
				// Translate the both sides.
				//
				operand lhs = cvt( *exp.lhs );
				operand rhs = cvt( *exp.rhs );

				// Push [<INS> Lhs 0 Rhs] and return Lhs.
				//
				force_clobber_register( lhs );
				block->push_back( { map_operator( op ),{ lhs, operand( 0, bitcnt_t( rhs.size() * 8 ) ), rhs } } );
				return lhs;
			}
			case math::operator_id::max_value:
			case math::operator_id::min_value:
			case math::operator_id::umax_value:
			case math::operator_id::umin_value:
			{
				// Unpack the expression by forcing re-simplification without
				// prettification requested and recurse.
				//
				return cvt( exp.clone().transform( [ ] ( auto& ) {} ) );
			}
			case math::operator_id::greater:
			case math::operator_id::greater_eq:
			case math::operator_id::equal:
			case math::operator_id::not_equal:
			case math::operator_id::less_eq:
			case math::operator_id::less:
			case math::operator_id::ugreater:
			case math::operator_id::ugreater_eq:
			case math::operator_id::uequal:
			case math::operator_id::unot_equal:
			case math::operator_id::uless_eq:
			case math::operator_id::uless:
			{
				// Allocate boolean temporary.
				//
				operand tmp = block->tmp( 1 );

				// Translate the both sides.
				//
				operand lhs = cvt( *exp.lhs );
				operand rhs = cvt( *exp.rhs );

				// Push [<INS> Tmp Lhs Rhs] and return Tmp.
				//
				block->push_back( { map_operator( op ),{ tmp, lhs, rhs } } );
				return tmp;
			}
			default:
				break;
		}

		unreachable();
		return {};
	}
};