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
			bool success = rules::for_each( rules::alternate_forms, [ & ] ( const rules::rule_entry& rule, const std::vector<expression>& forms )
			{
				// If we match the rules:
				//
				if ( auto sym_map = rules::match( exp, rule ) )
				{
					// For each form:
					//
					for ( auto& form : forms )
					{
						// Try simplifying, if we could not, continue onto next one.
						//
						auto new_exp = try_simplify( rules::remap( exp, *sym_map, form ), true );
						if ( !new_exp ) continue;

						// If complexity was reduced:
						//
						size_t complexity_1 = new_exp->complexity();
						if ( complexity_1 < complexity_0 )
						{
							// Recurse, write the result at exp, indicate success.
							//
							exp = try_simplify( *new_exp ).value_or( *new_exp ).declare_simple();
							return true;
						}
					}
				}
				return false;
			} );
			if ( success ) return exp;
		}

		// For each simplified form:
		//
		bool success = rules::for_each( rules::simplified_form, [ & ] ( const rules::rule_entry& rule, const expression& form )
		{
			// If we could apply the simplification rule:
			//
			if ( auto new_exp = rules::apply( exp, rule, form ) )
			{
				// Recurse, write the result at exp, indicate success.
				//
				exp = try_simplify( *new_exp, skip_top_level ).value_or( *new_exp ).declare_simple();
				return true;
			}
			return false;
		} );
		if ( success ) return exp;

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
