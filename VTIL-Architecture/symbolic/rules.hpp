#pragma once
#include <map>
#include <tuple>
#include "expression.hpp"
#include "variable.hpp"

namespace vtil::symbolic::rules
{
	// Symbolic variables used in rule creation:
	//
	static const expression A = { { L"α", 0 } };
	static const expression B = { { L"β", 0 } };
	static const expression C = { { L"λ", 0 } };

	// Special variables:
	//
	static const expression X = { { L"Σ", 0 } };
	static const expression Q = { { L"Ω", 0 } };
	static const expression S = { { L"π", 0 } }; // Does not accept constants.
	static const expression U = { { L"μ", 0 } }; // Only accepts constants.

	// Special functions used in rule creation:
	//
	static const auto bmask = [ ] ( const expression& a ) { return expression( find_opr( "__bmask" ), a ); };
	static const auto bcnt = [ ] ( const expression& a ) { return expression( find_opr( "__bcnt" ), a ); };
	static const auto bcntN = [ ] ( const expression& a, const expression& b ) { return expression( a, find_opr( "__bcntN" ), b ); };

	// All simpilfications:
	// - Note! Must not contain ( simplified[simplified[x]] == y ).
	//
	static const std::map<expression, expression> simplified_form =
	{
		// Inverse operations
		//
		{ -(-A), A },
		{ ~(~A), A },
		{ -(~A), A+1 },
		{ ~(-A), A-1 },

		// Identity constant
		//
		{ A+0, A },
		{ A-0, A },
		{ A|A, A },
		{ A|0, A },
		{ A&A, A },
		{ A^0, A },
		{ A&bmask(A), A },

		// Shift normalization
		//
		{ (A>>bcntN(B,A))|(A<<(bcntN(-B,A))), A.ror(B) },	// [imm shift -> imm rotation]
		{ (A<<bcntN(B,A))|(A>>(bcntN(-B,A))), A.rol(B) },	//
		{ (A>>bcntN(Q,A))>>bcntN(X,A), A>>(X+Q) },			// merge {imm shift x2}
		{ (A<<bcntN(Q,A))<<bcntN(X,A), A<<(X+Q) },			//
		{ (A>>S)|(A<<(bcnt(A)-S)), A.ror(S) },				// [var shift -> var rotation]
		{ (A<<S)|(A>>(bcnt(A)-S)), A.rol(S) },				//
		{ A.rol(bcntN(Q,A)), A.rol(Q) },					// normalize {imm rotation}
		{ A.ror(bcntN(Q,A)), A.ror(Q) },					//
		//{ A>>bcntN(Q,A), A>>Q },							// noramlize {imm shift}
		//{ A<<bcntN(Q,A), A<<Q },							//
		{ A>>bcntN(Q,A), {0} },								// noramlize {imm shift}
		{ A<<bcntN(Q,A), {0} },								//
		{ (A<<B)>>B, A&(bmask(A)>>B)},
		{ (A>>B)<<B, A&(bmask(A)<<B)},

		// Constant result
		//
		{ A-A, {0} },
		{ A+(-A), {0} },
		{ A&0, {0} },
		{ A^A, {0} },
		{ A&(~A), {0} },
		{ A|bmask(A), bmask(A) },
		{ A^(~A), bmask(A) },
		{ A|(~A), bmask(A) },
		{ A.rol(0), A },
		{ A.ror(0), A },
		{ A>>0, A },
		{ A<<0, A },

		// SUB conversion
		//
		{ (~A)+B, ~(A-B) },

		// NEG conversion
		//
		{ ~(A+bmask(A)), -A },
		{ (0-A), -A },

		// Simplify AND OR
		//
		{ A&(A|B),	A },
		{ A|(A&B),	A },
		
		{ ((A&X)|(B&Q))&(A|B),	(A&X)|(B&Q) },
		{ ((A&X)|(B&Q))&(A|B),	(A&X)|(B&Q) },
		{ ((A|X)&(B|Q))|(A&B),	(A|X)&(B|Q) },
		{ ((A|X)&(B|Q))|(A&B),	(A|X)&(B|Q) },
		// XOR|NAND|NOR -> NOT conversion
		//
		{ A^bmask(A), ~A },

		// XOR / OR / AND conversion
		//
		{ (~A)&(~B), ~(A|B) },
		{ (~A)|(~B), ~(A&B) },
		{ (A|B)&(~(A&B)), A^B },
		{ (A&(~B))|((~A)&B), A^B },
		{ ~((~(A|B))|(A&B)), A^B },
		
		// Prefer NEG over SUB
		//
		//{ A-B,	A+(-B) },

		// ADD to OR
		//
		{ ((~A)&B)+(A&C), ((~A)&B)|(A&C) }
	};

	// All alternate forms:
	// - Note: Both sides should contain the same amount of unknowns.
	//
	static const std::map<expression, expression> alternate_forms = 
	{
		// Distribute shift over bitwise operators
		//
		{ (A&B)>>C,	(A>>C)&(B>>C) },
		{ (A&B)<<C,	(A<<C)&(B<<C) },
		{ (A|B)>>C,	(A>>C)|(B>>C) },
		{ (A|B)<<C,	(A<<C)|(B<<C) },
		{ (A^B)>>C,	(A>>C)^(B>>C) },
		{ (A^B)<<C,	(A<<C)^(B<<C) },

		// Generic distribution
		//
		{ ~(A&B), (~A)|(~B) },
		{ ~(A|B), (~A)&(~B) },
		{ ~(A^B), (~A)^B },
		{ ~(A^B),  A^(~B) },

		{ A&(B|C), (A&B)|(A&C) },
		{ A|(B&C), (A|B)&(A|C) },
		
		{ A&(B&C), (A&B)&C },
		{ A|(B|C), (A|B)|C },
		
		{ A&(B&C), (A&B)&(A&C) },
		{ A|(B|C), (A|B)|(A|C) },
		{ A&(B^C), (A&B)^(A&C) },
		


		{ A+(B+C), (A+B)+C },
		{ A+(B+C), (A+C)+B },
		{ A-(B+C), (A-B)-C },
		{ A-(B+C), (A-C)-B },
		{ A-(B-C), (A-B)+C },
		{ A-(B-C), (A+C)-B },
		
		// Switch between NEG and SUB
		//
		{ A-B,	A+(-B) },
	};

	// Checks if the provided expression tree matches that of a symbolic 
	// tree simplification/alternate form and returns the table to map it 
	// so that they are equivalent.
	//
	template<bool bcnt_strict = true>
	static std::optional<symbol_map> match( const expression& input, const expression& target, const symbol_map& sym_map = {}, uint8_t op_size = 0 )
	{
		// If target is a variable.
		//
		if ( target.is_variable() )
		{
			// If constant, simply compare the values.
			//
			if ( target.value->is_constant() )
			{
				// Fail if input is not a constant.
				//
				if ( !input.is_variable() || !input.value->is_constant() )
					return {};

				// Determine operation size where possible.
				//
				if ( !op_size ) op_size = input.size();

				if ( target.value->get( op_size ) == input.value->get( op_size ) )
					return { sym_map };
				else
					return {};
			}

			// If symbolic map contains the target variable:
			//
			auto it = sym_map.find( *target.value );
			if ( it == sym_map.end() )
			{
				symbol_map sym_map_new = sym_map;

				// Check special conditions:
				//
				if ( target.value->uid == S.value->uid && input.is_constant() )
					return {};
				if ( target.value->uid == U.value->uid && !input.is_constant() )
					return {};

				sym_map_new[ *target.value ] = input;
				return { sym_map_new };
			}
			else
			{
				if ( it->second == input )
					return { sym_map };
				else
					return {};
			}
		}
		// If input is a variable and target is an expression.
		//
		else if ( input.is_variable() )
		{
			// If special functor:
			//
			if ( target.fn->function == "__bcntN" &&
				 input.is_constant() )
			{
				// Find which variable we're calculating this for.
				// - Referencing unknown variable in simplification condition if assert fail raises.
				//
				auto it = sym_map.find( *target[ 1 ].value );
				fassert( it != sym_map.end() );

				// Find the In/Out operand.
				//
				symbol_map sym_map_new = sym_map;
				expression* exp_out;
				int8_t sign = +1;
				if ( target[ 0 ].is_expression() )
				{
					// Unknown operation in simplification condition if this is hit.
					//
					fassert( target[ 0 ].fn->function == "neg" );
					sign = -1;
					exp_out = &sym_map_new[ *target[ 0 ][ 0 ].value ];
				}
				else
				{
					exp_out = &sym_map_new[ *target[ 0 ].value ];
				}

				// Calculate number of bits in the variable.
				//
				int8_t bit_count = it->second.size() * 8;
				fassert( bit_count != 0 );

				// If known variable, we're being asked to check if normalized form matches:
				//
				if ( exp_out->is_valid() )
				{
					// Fail if not constant.
					//
					if ( !exp_out->is_constant() )
						return {};

					int64_t value_a = ( ( bit_count + exp_out->value->get() ) % bit_count );
					int64_t value_b = ( ( bit_count + sign * input.value->get() ) % bit_count );
					if ( value_a == value_b )
						return { sym_map };
					else
						return {};
				}
				// If unknown variable, it's asking for normalized form:
				//
				else
				{
					// Skip if already normalized
					//
					int64_t value = sign * input.value->get();
					if ( 0 <= value && value < bit_count && bcnt_strict )
						return {};

					// Write normalized value and indicate success.
					//
					*exp_out = variable( ( ( bit_count + value ) % bit_count ), op_size );
					return { sym_map_new };
				}
			}
			// If constant maps to expression, try remapping 
			// and checking if it evaluates to the same value.
			//
			else if ( input.is_constant() )
			{
				expression copy = target;
				copy.remap_symbols( sym_map );
				if( copy.evaluate() == input.value )
					return { sym_map };
			}
			
			return {};
		}
		// If both are expressions.
		//
		else
		{
			// If operators mismatch:
			//
			if ( input.fn != target.fn )
			{
				return {};
			}
			// If matching operators, compare operands:
			//
			else
			{
				// Determine expected size:
				//
				op_size = input.size();

				// If unary operator:
				//
				std::optional<symbol_map> result;
				if ( input.fn->is_unary )
				{
					result = match<bcnt_strict>( input[ 0 ], target[ 0 ], sym_map, op_size );
				}
				// If binary operator:
				//
				else
				{
					// Check if operands match, in order:
					//
					result = match<bcnt_strict>( input[ 0 ], target[ 0 ], sym_map, op_size );
					if ( result.has_value() ) result = match<bcnt_strict>( input[ 1 ], target[ 1 ], result.value(), op_size );

					// Otherwise check if operator is commutative and operands match in reverse:
					//
					if ( !result.has_value() && input.fn->commutative == +1 )
					{
						result = match<bcnt_strict>( input[ 0 ], target[ 1 ], sym_map, op_size );
						if ( result.has_value() ) result = match<bcnt_strict>( input[ 1 ], target[ 0 ], result.value(), op_size );
					}
				}

				// Return the final result.
				//
				return result;
			}
		}
	}

	// Transforms between equivalent expression trees.
	//
	template<bool bcnt_strict = true>
	static expression remap_equivalent( const expression& input, const expression& from, const expression& to )
	{
		// All variables should be of the same size.
		//
		fassert( input.is_normalized() );

		// Check if equivalent, if not return invalid expression.
		//
		auto sym_map = match<bcnt_strict>( input, from );
		if ( !sym_map )
			return {};

		// Remap symbol.
		//
		expression new_expression = to;
		new_expression.remap_symbols( *sym_map );

		// Remove any remaining special instructions
		//
		std::function<void( expression& )> remove_special = [ & ] ( expression& r )
		{
			if ( r.fn && r.fn->function[ 0 ] == '_' )
			{
				if ( auto val = r.evaluate() )
				{
					r = *val;
					return;
				}
			}
			for ( auto& op : r.operands )
				remove_special( op );
		};
		remove_special( new_expression );
		return new_expression.resize( input.size() );
	}
}