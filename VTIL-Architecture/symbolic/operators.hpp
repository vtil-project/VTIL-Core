#pragma once
#include <map>
#include <string>
#include <vector>
#include <platform.hpp>

namespace vtil::symbolic
{
	// Generic operator description.
	//
	struct operator_desc
	{
		// Symbolic identifier for this operator.
		//
		// If [symbol] is empty:
		//		to_string(...) =>	function(split(..., ','))
		// else:
		//		to_string(x) =>		concat(symbol, x)
		//		to_string(...) =>	split(..., symbol)
		//
		std::string function;
		std::string symbol;

		// Whether this is a unary operator or not.
		//
		bool is_unary;

		// Whether this is a bitwise operator or not.
		//
		bool is_bitwise;

		// Whether (anti-)commutative property is applicable or not.
		// N/A if 0, anti-commutative if -1, commutative if +1.
		int8_t commutative;

		// Type of result size, min if -1, max if +1, first operand if 0.
		//
		int8_t result_size;

		// Null and identity operands in terms of x.
		//
		std::vector<std::string> null_operand;
		std::vector<std::string> identity_operand;
	};

	// List of all operators.
	//
	static const std::vector<operator_desc> operator_map =
	{
		// [Name]  [Symbol] [Unary?] [Bitwise?] [Commutative] [RSize] //
		{ "neg",   "-",      true,   false,      0,            0,     },
		{ "not",   "~",      true,    true,      0,            0,     },
				 													  	 
		{ "add",   "+",     false,   false,     +1,           +1,     },
		{ "sub",   "-",     false,   false,     -1,           +1,     },
				 													  	 
		{ "or" ,   "|",     false,    true,     +1,           +1,     },
		{ "and",   "&",     false,    true,     +1,           -1,     },
		{ "xor",   "^",     false,    true,     +1,           +1,     },
		{ "shr",   ">>",    false,    true,      0,            0,     },
		{ "shl",   "<<",    false,    true,      0,            0,     },
		{ "ror",   ">]",    false,    true,      0,            0,     },
		{ "rol",   "[<",    false,    true,      0,            0,     },

		// Special operands for simplification instructions:
		//
		
		// Variable resize:
		// - Hints the output that variable was resized.
		//
		{ "new",   "",      false,    true,      0,           -1,     },

		// Bit-Count Normalize:
		// - Evaluates to op#1 % bcnt(op#2) [Note: Will only match if op#1 >= bcnt(op#2) || op#1 < 0]
		//
		{ "bcntN", "",      false,    true,      0,            0,     },

		// Bit-Mask:
		// - Evaluates to ~{0 of size op#1}
		//
		{ "bmask", "",      true,    true,       0,            0,     },
	};

	// Searcher for an operator within the string provided.
	//
	static const operator_desc* lookup( const std::string& s, bool partial, bool prefix )
	{
		// For each operator in the list:
		//
		for ( auto& desc : operator_map )
		{
			// Match symbols only if we're looking for a suffix or 
			// this is a unary operator.
			//
			if ( !prefix || desc.is_unary )
			{
				if ( !desc.symbol.empty() && ( partial ? s.starts_with( desc.symbol ) : s == desc.symbol ) )
					return &desc;
			}

			// Match function names only if we're looking for a prefix.
			//
			if ( prefix && ( partial ? s.starts_with( desc.function ) : s == desc.function ) )
			{
				return &desc;
			}
		}
		return nullptr;
	}

	// Convinience wrapper for (what would be, if the map was not const) operator_map[name].
	//
	static const operator_desc* find_opr( const std::string& name )
	{
		// For each operator in the list:
		//
		for ( auto& desc : operator_map )
		{
			if ( desc.function == name )
				return &desc;
		}
		unreachable();
	}
};