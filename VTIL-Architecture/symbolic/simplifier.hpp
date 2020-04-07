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
	static std::optional<expression> try_simplify( const expression& input, bool skip_top_level = false )
	{
		// Assert we received a valid expression.
		//
		fassert( input.is_valid() );

		// If expression is already in the simplest form possible, return as is.
		//
		if ( input.is_simplest_form )
			return {};

		// Simplify children.
		//
		expression exp = input;
		bool simplified_child = false;
		for ( auto& op : exp.operands )
		{
			if ( op.is_simplest_form )
				continue;
			if ( auto r = try_simplify( op ) )
				simplified_child = true, op = r.value();
			op.declare_simple();
		}

		// Try evaluating current expression, if we could
		// return it as is.
		//
		if ( auto eval = input.evaluate() )
			return eval.value();

		// If top level is to be simplified:
		//
		if ( !skip_top_level )
		{
			// For each alternate form:
			//
			size_t complexity_0 = exp.complexity();
			for ( auto& pair : rules::alternate_forms )
			{
				auto sym_map = rules::match( input, pair.first );
				if ( !sym_map )
					continue;

				for ( auto& form : pair.second )
				{
					auto new_exp = try_simplify( rules::remap( exp, *sym_map, form ), true );
					if ( !new_exp ) continue;

					size_t complexity_1 = new_exp->complexity();
					if ( complexity_1 < complexity_0 )
					{
						return try_simplify( *new_exp ).value_or( *new_exp ).declare_simple();
					}
				}
			}
		}

		// For each simplified form:
		//
		for ( auto& pair : rules::simplified_form )
		{
			// Check if our tree matches the input format:
			//
			auto new_exp = rules::apply( exp, pair.first, pair.second );
			if ( new_exp.is_valid() )
			{
				// Recurse.
				//
				return try_simplify( new_exp, skip_top_level ).value_or( new_exp ).declare_simple();
			}
		}

		// Try evaluating new expression, if we could
		// return it as is.
		//
		if ( auto eval = exp.evaluate() )
			return eval.value();

		// If we simplified a child, still declare simple and return. 
		//
		if ( simplified_child )
			return exp.declare_simple();
		return {};
	}
	static expression simplify( expression input )
	{
		// TODO: Fix equivalent registers of different size being in the variable

		// Fail if input is invalid.
		//
		if ( !input.is_valid() )
			return {};

		// Explicitly resize the expression to output size.
		//
		input.resize( input.size() );

		// Try simplifying the expression, and declare simple.
		//
		if ( auto r = try_simplify( input ) )
			input = r.value();
		return input.resize( input.size() ).declare_simple();
	}

	// Checks whether the two given expressions are equivalent in a more reliable
	// fashion when compared to simply invoking expression::operator==(...)
	//
	static bool is_equivalent( const expression& a, const expression& b )
	{
		// If naive-comparison returns equivalent, return so.
		//
		if ( a == b )
			return true;

		// Try matching the simplification of an expression that 
		// would be zero if a and be were equivalent instead 
		// otherwise to cause a much more complex evaluation.
		//
		return simplify( a - b ) == variable{ 0 };
	}
};
