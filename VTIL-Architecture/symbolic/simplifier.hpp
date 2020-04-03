#pragma once
#include <map>
#include <optional>
#include "rules.hpp"
#include "expression.hpp"
#include "variable.hpp"
#include "operators.hpp"

namespace vtil::symbolic
{
	// Tries to simplify the given symbolic expression as much as possible.
	//
	static expression simplify( const expression& input, bool* simplified = nullptr )
	{
		// Assert we received a valid expression.
		//
		fassert( input.is_valid() );

		// If exprssion is a variable/is already in
		// the simplest form possible, return as is.
		//
		if ( input.is_simplest_form )
			return input;

		// Simplify children.
		//
		expression exp = input;
		for ( auto& op : exp.operands )
			op = simplify( op, simplified );

		// Try evaluating current expression, if we could
		// return it as is.
		//
		if ( auto eval = input.evaluate() )
		{
			if ( simplified ) *simplified = true;
			return eval.value();
		}

		// For each alternate form:
		//
		std::vector<std::pair<size_t, expression>> forms;
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
					op = simplify( op, &sub_simplified );

				// If complexity did not change but we've
				// simplified any operands at all, return the
				// new expression as is.
				//
				size_t complexity_1 = new_exp.complexity();
				if ( complexity_1 == complexity_0 && sub_simplified )
				{
					exp = new_exp;
					if ( simplified ) *simplified = true;
					break;
				}
				// If complexity reduced, recurse:
				//
				else if ( complexity_1 < complexity_0 )
				{
					return simplify( new_exp );
				}
			}
		}

		// For each simplified form:
		//
		for ( auto& pair : rules::simplified_form )
		{
			// Check if our tree matches the input format:
			//
			auto new_exp = rules::remap_equivalent( exp, pair.first, pair.second );
			if ( new_exp.is_valid() )
			{
				// Recurse.
				//
				if ( simplified ) *simplified = true;
				return simplify( new_exp );
			}
		}

		// Try evaluating new expression, if we could
		// return it as is.
		//
		if ( auto eval = exp.evaluate() )
		{
			if ( simplified ) *simplified = true;
			return eval.value();
		}
		return exp.declare_simple();
	}
};
