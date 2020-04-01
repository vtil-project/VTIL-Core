#pragma once
#include <map>
#include <optional>
#include "rules.hpp"
#include "expression.hpp"
#include "variable.hpp"
#include "operators.hpp"

namespace vtil::symbolic
{
	// Tries to evaluate the numeric value of a symbolic expression.
	//
	static std::optional<variable> evaluate( const expression& exp )
	{
		// If expression is a boxed variable, return as is.
		//
		if ( exp.is_variable() )
			return exp.is_constant() ? exp.value : std::nullopt;

		// If expression contains any non-constant operands, report failure.
		//
		for ( auto& op : exp.operands )
			if ( !op.is_constant() )
				return {};

		// ------- Unary operators ------- //
		variable o1 = *exp[ 0 ].value;
		if ( exp.fn->function == "neg" )
			return variable{ -o1.get<true>( 0 ), o1.size };
		else if ( exp.fn->function == "not" )
			return variable{ ~o1.get<false>( 0 ), o1.size };
		else if ( exp.fn->function == "bmask" )
			return variable{ ~0ull >> ( 64 - o1.size * 8 ), o1.size };

		// ------- Binary operators ------- //
		variable o2 = *exp[ 1 ].value;
		size_t ns = exp.size();
		if ( exp.fn->function == "or" )
			return variable{ o1.get<false>( 0 ) | o2.get<false>( 0 ), ns };
		else if ( exp.fn->function == "and" )
			return variable{ o1.get<false>( 0 ) & o2.get<false>( 0 ), ns };
		else if ( exp.fn->function == "xor" )
			return variable{ o1.get<false>( 0 ) ^ o2.get<false>( 0 ), ns };
		else if ( exp.fn->function == "shr" )
			return variable{ o1.get<false>( 0 ) >> o2.get<false>( 0 ), ns };
		else if ( exp.fn->function == "shl" )
			return variable{ o1.get<false>( 0 ) << o2.get<false>( 0 ), ns };
		else if ( exp.fn->function == "ror" )
			return variable{ ( o1.get<false>( 0 ) >> o2.get<false>( 0 ) ) | ( o1.get<false>( 0 ) << ( o1.size * 8 - o2.get<false>( 0 ) ) ), ns };
		else if ( exp.fn->function == "rol" )
			return variable{ ( o1.get<false>( 0 ) << o2.get<false>( 0 ) ) | ( o1.get<false>( 0 ) >> ( o1.size * 8 - o2.get<false>( 0 ) ) ), ns };
		else if ( exp.fn->function == "add" )
			return variable{ o1.get<true>( 0 ) + o2.get<true>( 0 ), ns };
		else if ( exp.fn->function == "sub" )
			return variable{ o1.get<true>( 0 ) - o2.get<true>( 0 ), ns };
		
		// Other operators should not reach here.
		return {};
	}

	// Tries to simplify the given symbolic expression as much as possible.
	//
	static std::pair<expression, bool> simplify( const expression& input )
	{
		// Assert we received a valid expression.
		//
		fassert( input.is_valid() );

		// Try evaluating current expression, if we could
		// return it as is.
		//
		if ( auto eval = evaluate( input ) )
			return { eval.value(), true };

		// Simplify children.
		//
		bool simplifed = false;
		expression exp = input;
		for ( auto& op : exp.operands )
		{
			auto r = simplify( op );
			op = r.first;
			simplifed |= r.second;
		}

		// If result is a variable, return it.
		//
		if ( exp.is_variable() )
			return { exp, simplifed };

		// For each simplified form:
		//
		for ( auto& pair : rules::simplified_form )
		{
			// Check if our tree matches the input format:
			//
			auto new_exp = rules::remap_equivalent( exp, pair.first, pair.second );
			if ( new_exp.is_valid() )
			{
				// Simplify children again and assign the equivalent.
				//
				exp = new_exp;
				for ( auto& op : exp.operands )
					op = simplify( op ).first;
				simplifed = true;
			}
		}

		// For each alternate form:
		//
		size_t complexity_0 = exp.complexity();
		for ( auto& pair : rules::alternate_forms )
		{
			// Try replacing x => y and y => x
			//
			auto new_exp = rules::remap_equivalent( exp, pair.first, pair.second );
			if( !new_exp.is_valid() )
				new_exp = rules::remap_equivalent( exp, pair.second, pair.first );

			// If we found a match:
			//
			if ( new_exp.is_valid() )
			{
				// Simplify children.
				//
				bool sub_simplified = false;
				for ( auto& op : new_exp.operands )
				{
					auto [op_new, ssimplified] = simplify( op );
					op = op_new;
					sub_simplified |= ssimplified;
				}
				
				// If complexity did not change but we've
				// simplified any operands at all, return the
				// new expression as is.
				//
				size_t complexity_1 = new_exp.complexity();
				if ( complexity_1 == complexity_0 && sub_simplified )
				{
					exp = new_exp;
					simplifed = true;
					break;
				}

				// If complexity reduced, recurse:
				//
				else if ( complexity_1 < complexity_0 )
					return simplify( new_exp );
			}
		}

		// Try evaluating new expression, if we could
		// return it as is.
		//
		if ( auto eval = evaluate( exp ) )
			return { eval.value(), true };

		return { exp, simplifed };
	}
};
