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
#pragma once
#include <map>
#include "directive.hpp"
#include "..\expressions\expression.hpp"

namespace vtil::symbolic::directive
{
	static bool trx_verbose = false;

	// Internal representation of the Variable -> Expression mapping.
	//
	struct symbol_table
	{
		std::map<const char*, expression::reference> variable_map;

		bool add( const instance::reference& dir, const expression::reference& exp )
		{
			// If it's the first time this variable is being used:
			//
			auto it = variable_map.find( dir->id );
			if ( it == variable_map.end() )
			{
				// Check if the matching condition is met.
				//
				switch ( dir->mtype )
				{
					case match_any:                                                                   break;
					case match_variable:               if ( !exp->is_variable()   )   return false;   break;
					case match_constant:               if ( !exp->is_constant()   )   return false;   break;
					case match_expression:             if ( !exp->is_expression() )   return false;   break;
					case match_variable_or_constant:   if (  exp->is_expression() )   return false;   break;
					default: unreachable();
				}

				// Save the mapping of this symbol and return success.
				//
				variable_map[ dir->id ] = exp;
				return true;
			}
			else
			{
				// Check if saved expression is equivalent, if not fail.
				//
				return it->second->equals( *exp );
			}
		}

		expression::reference translate( const instance::reference& dir ) const
		{
			// Lookup the map for the variable
			//
			auto it = variable_map.find( dir->id );

			// Return the saved variable if found or else null reference.
			//
			return it != variable_map.end() ? it->second : expression::reference{};
		}
	};

	static expression::reference translate( const symbol_table& sym,
											const instance::reference& dir,
											uint8_t bitcnt,
											bool speculative_condition )
	{
		using namespace logger;

		scope_padding _p( 1 );
		if ( trx_verbose ) log<CON_BLU>( "[%s].\n", dir->to_string() );

		// Dummy expression used just to indicate success if speculative_condition is used, if seen in
		// output of the simplifier, there's a major bug.
		//
		static const expression::reference dummy_expression = expression{ "@dummmy", 1 };

		// If expression operator:
		//
		if ( dir->op < math::operator_id::max )
		{
			// If directive is a variable or a constant, translate to expression equivalent.
			//
			if ( dir->op == math::operator_id::invalid )
			{
				if ( !dir->id ) return expression{ dir->get().value(), bitcnt };
				else            return sym.translate( dir );
			}
			// If it is an expression:
			//
			else
			{
				// If speculative condition parsing no need to build an expression, simplfy
				// check if all operands can also be speculatively built.
				//
				if ( speculative_condition )
				{
					if ( dir->lhs && !translate( sym, dir->lhs, bitcnt, true ) ) return {};
					if ( !translate( sym, dir->rhs, bitcnt, true ) ) return {};
					return dummy_expression;
				}

				// Handle casts as a redirect to resize.
				//
				if ( dir->op == math::operator_id::ucast ||
					 dir->op == math::operator_id::cast )
				{
					auto lhs = translate( sym, dir->lhs, bitcnt, speculative_condition );
					if ( !lhs )	return {};
					auto rhs = translate( sym, dir->rhs, bitcnt, speculative_condition );
					if ( !rhs ) return {};
					
					if ( auto sz = rhs->get() )
					{
						( +lhs )->resize( sz.value(), dir->op == math::operator_id::cast );
						return lhs;
					}
					unreachable();
				}
				// If operation is binary:
				//
				else if ( dir->lhs )
				{
					auto lhs = translate( sym, dir->lhs, bitcnt, speculative_condition );
					if ( !lhs )	return {};
					auto rhs = translate( sym, dir->rhs, bitcnt, speculative_condition );
					if ( !rhs ) return {};
					return expression::make( lhs, dir->op, rhs );
				}
				// If operation is unary:
				//
				else
				{
					auto rhs = translate( sym, dir->rhs, bitcnt, speculative_condition );
					if ( !rhs ) return {};
					return expression::make( dir->op, rhs );
				}
			}
			unreachable();
		}

		// If directive operator:
		//
		switch ( directive_op_desc{ dir->op }.value )
		{
			case directive_op_desc::simplify:
			{
				// If expression translates successfully: (Unset speculative_condition flag)
				//
				if ( auto e1 = translate( sym, dir->rhs, bitcnt, false ) )
				{
					// Return only if it was successful.
					//
					if ( !e1->simplify_hint && simplify_expression( e1 ) )
						return e1;
				}
				if ( trx_verbose ) log<CON_RED>( "Rejected, does not simplify.\n", dir->rhs->to_string() );
				break;
			}
			case directive_op_desc::try_simplify:
			{
				// Translate right hand side.
				//
				if ( auto e1 = translate( sym, dir->rhs, bitcnt, speculative_condition ) )
				{
					// Simplify the expression if not dummy (generated by speculative checks).
					//
					if ( !speculative_condition )
						simplify_expression( e1 );
					return e1;
				}
				break;
			}
			case directive_op_desc::or_also:
			{
				if ( trx_verbose ) log<CON_BLU>( "Or directive hit %s.\n" );
				if ( trx_verbose ) log<CON_BLU>( "Trying [%s]...\n", dir->lhs->to_string() );

				// Unpack first expression, if translated successfully, return it as is.
				//
				if ( auto e1 = translate( sym, dir->lhs, bitcnt, speculative_condition ) )
					return e1;
				if ( trx_verbose ) log<CON_BLU>( "Trying [%s]...\n", dir->rhs->to_string() );

				// Unpack second expression, if translated successfully, return it as is.
				//
				if ( auto e2 = translate( sym, dir->rhs, bitcnt, speculative_condition ) )
					return e2;
				if ( trx_verbose ) log<CON_RED>( "Both alternatives failed\n" );
				break;
			}
			case directive_op_desc::iff:
			{
				// Translate left hand side, if failed to do so or is not equal to [true], fail.
				//
				auto condition_status = translate( sym, dir->lhs, bitcnt, false );
				if ( !condition_status || !(+condition_status)->simplify().get().value_or( false ) )
				{
					if ( trx_verbose ) log<CON_RED>( "Rejected %s, condition (%s) not met.\n", dir->rhs->to_string(), dir->lhs->to_string() );
					return {};
				}

				// Continue the translation from the right hand side.
				//
				return translate( sym, dir->rhs, bitcnt, speculative_condition );
			}
			case directive_op_desc::mask_unknown:
			{
				// Translate right hand side.
				//
				if ( auto exp = translate( sym, dir->rhs, bitcnt, speculative_condition ) )
				{
					// Return the unknown mask.
					//
					return expression{ exp->unknown_mask(), exp->size() };
				}
				break;
			}
			case directive_op_desc::mask_one:
			{
				// Translate right hand side.
				//
				if ( auto exp = translate( sym, dir->rhs, bitcnt, speculative_condition ) )
				{
					// Return the unknown mask.
					//
					return expression{ exp->known_one(), exp->size() };
				}
				break;
			}
			case directive_op_desc::mask_zero:
			{
				// Translate right hand side.
				//
				if ( auto exp = translate( sym, dir->rhs, bitcnt, speculative_condition ) )
				{
					// Return the unknown mask.
					//
					return expression{ exp->known_zero(), exp->size() };
				}
				break;
			}
			case directive_op_desc::unreachable:
			{
				// Print an error.
				//
				log<CON_RED>( "Directive-time assertation failure!\n" );

				// Break execution.
				//
				unreachable();
			}
			case directive_op_desc::warning:
			{
				// Print a warning.
				//
				log<CON_YLW>( "WARNING!\n" );

				// Continue the translation from the right hand side.
				//
				return translate( sym, dir->rhs, bitcnt, speculative_condition );
			}
			default:
				unreachable();
		}

		// Failed translating the directive.
		//
		return {};
	}

	static bool match( symbol_table& sym, const instance::reference& dir, const expression::reference& exp, const instance::reference& test_dir, uint8_t bit_cnt, bool is_tail = true )
	{
		// If directive is a constant or a variable:
		//
		if ( dir->op == math::operator_id::invalid )
		{
			// If directive is a variable:
			//
			if ( dir->id )
			{
				if ( !sym.add( dir, exp ) )
					return false;
			}
			// If directive is a constant:
			//
			else
			{
				// Generate mask for the size of the constant and compare the masked values
				// if expression is also a constant, else fail.
				//
				uint64_t mask = math::mask( exp->size() );
				if ( !exp->is_constant() || ( exp->value.known_one() & mask ) != ( dir->value.known_one() & mask ) )
					return false;
			}

			// If we're the tail and we finished matching, try speculative mapping,
			// otherwise simply report success.
			//
			if ( is_tail ) return translate( sym, test_dir, bit_cnt, true );
			else           return true;
		}
		// If directive is an expression and the operators are the same
		//
		else if ( exp->op == dir->op )
		{
			// Resolve operator descriptor, if unary, just compare right hand side.
			//
			const math::operator_desc* desc = exp->get_op_desc();
			if ( desc->operand_count == 1 )
				return match( sym, dir->rhs, exp->rhs, test_dir, bit_cnt, is_tail );

			// Save the previous symbol table, check if we can match operands as is,
			// if we succeed in doing so, indiciate success.
			//
			symbol_table symt0 = sym;
			if ( match( symt0, dir->lhs, exp->lhs, test_dir, bit_cnt, false ) &&
				 match( symt0, dir->rhs, exp->rhs, test_dir, bit_cnt, is_tail ) )
			{
				sym = symt0;
				return true;
			}

			// Restore the previous symbol table, check if we can match operands in 
			// reverse, if we succeed in doing so, indiciate success.
			//
			symbol_table symt1 = sym;
			if ( desc->is_commutative &&
				 match( symt1, dir->rhs, exp->lhs, test_dir, bit_cnt, false ) &&
				 match( symt1, dir->lhs, exp->rhs, test_dir, bit_cnt, is_tail ) )
			{
				sym = symt1;
				return true;
			}
		}

		// Generic fail case.
		//
		return false;
	}

	static expression::reference transform( const expression::reference& exp, const instance::reference& from, const instance::reference& to )
	{
		using namespace logger;
		// If expression does not match the "from" directive or 
		// if constraints are not satisfied during speculative parsing, fail.
		//
		symbol_table sym;
		if ( !match( sym, from, exp, to, exp->size() ) ) return {};
		
		// If all pre-conditions are met, request translation for the actual output.
		//
		if ( trx_verbose )
		{
			log<CON_BLU>( "Translating [%s] => [%s]:\n", from->to_string(), to->to_string() );
			for ( auto& [var, exp] : sym.variable_map )
				log<CON_BLU>( "            %s: %s\n", var, exp->to_string() );
		}
		if ( auto exp_new = translate( sym, to, exp->size(), false ) )
		{
			if ( trx_verbose ) log<CON_GRN>( "Success.\n" );
			return exp_new;
		}
		else
		{
			if ( trx_verbose ) log<CON_RED>( "Failure.\n" );
			return {};
		}
	}

};