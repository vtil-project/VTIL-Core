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
#include "matcher.hpp"
#include "..\simplifier\simplifier.hpp"

namespace vtil::symbolic::directive
{
	static bool match_verbose = false;

	// Translates the given directive into an expression (of size given) using the symbol table.
	// - If speculative flag is set, it will either return a dummy reference if the expression could be built,
	//   or a null reference if it would fail.
	//
	expression::reference translate( const symbol_table& sym,
									 const instance::reference& dir,
									 bitcnt_t bit_cnt,
									 bool speculative_condition )
	{
		using namespace logger;
		scope_padding _p( 1 );
		if ( match_verbose ) log<CON_BLU>( "[%s].\n", dir->to_string() );

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
				if ( !dir->id ) return expression{ dir->get().value(), bit_cnt };
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
					if ( dir->lhs && !translate( sym, dir->lhs, bit_cnt, true ) ) return {};
					if ( !translate( sym, dir->rhs, bit_cnt, true ) ) return {};
					return dummy_expression;
				}

				// Handle casts as a redirect to resize.
				//
				if ( dir->op == math::operator_id::ucast ||
					 dir->op == math::operator_id::cast )
				{
					auto lhs = translate( sym, dir->lhs, bit_cnt, speculative_condition );
					if ( !lhs )	return {};
					auto rhs = translate( sym, dir->rhs, bit_cnt, speculative_condition );
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
					auto lhs = translate( sym, dir->lhs, bit_cnt, speculative_condition );
					if ( !lhs )	return {};
					auto rhs = translate( sym, dir->rhs, bit_cnt, speculative_condition );
					if ( !rhs ) return {};
					return expression::make( lhs, dir->op, rhs );
				}
				// If operation is unary:
				//
				else
				{
					auto rhs = translate( sym, dir->rhs, bit_cnt, speculative_condition );
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
				if ( auto e1 = translate( sym, dir->rhs, bit_cnt, false ) )
				{
					// Return only if it was successful.
					//
					if ( !e1->simplify_hint && simplify_expression( e1 ) )
						return e1;
				}
				if ( match_verbose ) log<CON_RED>( "Rejected, does not simplify.\n", dir->rhs->to_string() );
				break;
			}
			case directive_op_desc::try_simplify:
			{
				// Translate right hand side.
				//
				if ( auto e1 = translate( sym, dir->rhs, bit_cnt, speculative_condition ) )
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
				if ( match_verbose ) log<CON_BLU>( "Or directive hit %s.\n" );
				if ( match_verbose ) log<CON_BLU>( "Trying [%s]...\n", dir->lhs->to_string() );

				// Unpack first expression, if translated successfully, return it as is.
				//
				if ( auto e1 = translate( sym, dir->lhs, bit_cnt, speculative_condition ) )
					return e1;
				if ( match_verbose ) log<CON_BLU>( "Trying [%s]...\n", dir->rhs->to_string() );

				// Unpack second expression, if translated successfully, return it as is.
				//
				if ( auto e2 = translate( sym, dir->rhs, bit_cnt, speculative_condition ) )
					return e2;
				if ( match_verbose ) log<CON_RED>( "Both alternatives failed\n" );
				break;
			}
			case directive_op_desc::iff:
			{
				// Translate left hand side, if failed to do so or is not equal to [true], fail.
				//
				auto condition_status = translate( sym, dir->lhs, bit_cnt, false );
				if ( !condition_status || !( +condition_status )->simplify().get().value_or( false ) )
				{
					if ( match_verbose ) log<CON_RED>( "Rejected %s, condition (%s) not met.\n", dir->rhs->to_string(), dir->lhs->to_string() );
					return {};
				}

				// Continue the translation from the right hand side.
				//
				return translate( sym, dir->rhs, bit_cnt, speculative_condition );
			}
			case directive_op_desc::mask_unknown:
			{
				// Translate right hand side.
				//
				if ( auto exp = translate( sym, dir->rhs, bit_cnt, speculative_condition ) )
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
				if ( auto exp = translate( sym, dir->rhs, bit_cnt, speculative_condition ) )
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
				if ( auto exp = translate( sym, dir->rhs, bit_cnt, speculative_condition ) )
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
				return translate( sym, dir->rhs, bit_cnt, speculative_condition );
			}
			default:
				unreachable();
		}

		// Failed translating the directive.
		//
		return {};
	}

	// Tries to match the the given expression with the directive and fills the symbol table with
	// the variable mapping it would be a valid match, target directive can be passed if the caller
	// requires speculative validation of the translation into another directive. This argument will
	// not be propagated when recursing if it is not a tail call.
	//
	bool match( symbol_table& sym,
				const instance::reference& dir,
				const expression::reference& exp,
				uint8_t bit_cnt,
				const instance::reference& target_directive )
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
				uint64_t mask = math::fill( exp->size() );
				if ( !exp->is_constant() || ( exp->value.known_one() & mask ) != ( dir->value.known_one() & mask ) )
					return false;
			}

			// If target directive is valid, this implies we're the tail call and as
			// we matched with a variable, we will not recurse any deeper. Since we've 
			// reached the end of this check, try speculatively mapping to the target and
			// return failure if it fails.
			//
			if ( target_directive )
				return translate( sym, bit_cnt, target_directive, true );
			return true;
		}
		// If directive is an expression and the operators are the same
		//
		else if ( exp->op == dir->op )
		{
			// Resolve operator descriptor, if unary, just compare right hand side.
			//
			const math::operator_desc* desc = exp->get_op_desc();
			if ( desc->operand_count == 1 )
				return match( sym, dir->rhs, exp->rhs, bit_cnt, target_directive );

			// Save the previous symbol table, check if we can match operands as is,
			// if we succeed in doing so, indiciate success.
			//
			symbol_table symt0 = sym;
			if ( match( symt0, dir->lhs, exp->lhs, bit_cnt, {} ) &&
				 match( symt0, dir->rhs, exp->rhs, bit_cnt, target_directive ) )
			{
				sym = symt0;
				return true;
			}

			// Restore the previous symbol table, check if we can match operands in 
			// reverse, if we succeed in doing so, indiciate success.
			//
			symbol_table symt1 = sym;
			if ( desc->is_commutative &&
				 match( symt1, dir->rhs, exp->lhs, bit_cnt, {} ) &&
				 match( symt1, dir->lhs, exp->rhs, bit_cnt, target_directive ) )
			{
				sym = symt1;
				return true;
			}
		}

		// Generic fail case.
		//
		return false;
	}

	// Attempts to transform the expression in form A to form B as indicated by the directives.
	//
	expression::reference transform( const expression::reference& exp, const instance::reference& from, const instance::reference& to )
	{
		using namespace logger;

		// If expression does not match the "from" directive or 
		// if constraints are not satisfied during speculative parsing, fail.
		//
		symbol_table sym;
		if ( !match( sym, from, exp, to, exp->size() ) ) return {};

		// If all pre-conditions are met, request translation for the actual output.
		//
		if ( match_verbose )
		{
			log<CON_BLU>( "Translating [%s] => [%s]:\n", from->to_string(), to->to_string() );
			for ( auto& [var, exp] : sym.variable_map )
				log<CON_BLU>( "            %s: %s\n", var, exp->to_string() );
		}
		if ( auto exp_new = translate( sym, to, exp->size(), false ) )
		{
			if ( match_verbose ) log<CON_GRN>( "Success.\n" );
			return exp_new;
		}
		else
		{
			if ( match_verbose ) log<CON_RED>( "Failure.\n" );
			return {};
		}
	}
};