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
	static const expression Q = { { L"Σ", 0 } };
	static const expression _0 = { { 0, 0 } };

	// Special functions used in rule creation:
	//
	static const auto bmask = [ ] ( const expression& b ) { return expression( find_opr( "bmask" ), b ); };
	static const auto bcntN = [ ] ( const expression& a, const expression& b ) { return expression( a, find_opr( "bcntN" ), b ); };
	static const auto resize = [ ] ( const expression& a, const expression& b ) { return expression( a, find_opr( "new" ), b ); };

	// All simpilfications:
	// - Note! Must not contain ( simplified[simplified[x]] == y ).
	//
	static const std::map<expression, expression> simplified_form =
	{
		// Inverse operations
		//
		{ -(-A), A },
		{ ~(~A), A },

		// Identity constant
		//
		{ A+_0, A },
		{ A-_0, A },
		{ A|A, A },
		{ A|_0, A },
		{ A&A, A },
		{ A^_0, A },
		{ A&bmask(A), A },

		// Variable resizing
		//
		{ A&resize(A,Q), Q },

		// Shift normalization
		//
		{ A.rol(bcntN(Q,A)), A.rol(Q) },
		{ A.ror(bcntN(Q,A)), A.ror(Q) },
		{ A>>bcntN(Q,A), _0 },
		{ A<<bcntN(Q,A), _0 },
		{ A>>_0, A },
		{ A<<_0, A },
		{ A.rol(_0), A },
		{ A.ror(_0), A },

		// Constant result
		//
		{ A-A, _0 },
		{ A+(-A), _0 },
		{ A&_0, _0 },
		{ A^A, _0 },
		{ A&(~A), _0 },
		{ A|bmask(A), bmask(A) },
		{ A^(~A), bmask(A) },
		{ A|(~A), bmask(A) },

		// SUB conversion
		//
		{ (~A)+B, ~(A-B) },

		// NEG conversion
		//
		{ ~(A+bmask(A)), -A },
		{ (_0-A), -A },

		// Simplify AND OR
		//
		{ A&(A|B),	A },
		{ A|(A&B),	A },

		// Shift merging
		//
		{ (A>>B)>>C, A>>(B+C) },
		{ (A<<B)<<C, A<<(B+C) },

		// XOR|NAND|NOR -> NOT conversion
		//
		{ A^bmask(A), ~A },

		// ROR / ROL conversion
		{ (A>>B)|(A<<(bcntN(-B,A))), A.ror(B) },
		{ (A<<B)|(A>>(bcntN(-B,A))), A.rol(B) },

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
		{ A&(B^C), (A&B)^(A&C) },
		{ A&(B&C), (A&B)&C },
		{ A|(B&C), (A|B)&(A|C) },
		{ A|(B|C), (A|B)|C },
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
	static std::pair<bool, symbol_map> is_equivalent( const expression& input, const expression& target, const symbol_map& sym_map = {}, uint8_t op_size = 0 )
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
					return { false, {} };

				// Determine operation size where possible.
				//
				if ( !op_size ) op_size = input.size();

				if ( target.value->get( op_size ) == input.value->get( op_size ) )
					return { true, sym_map };
				else
					return { false,{} };
			}

			// If symbolic map contains the target variable:
			//
			auto it = sym_map.find( *target.value );
			if ( it == sym_map.end() )
			{
				symbol_map sym_map_new = sym_map;
				sym_map_new[ *target.value ] = input;
				return { true, sym_map_new };
			}
			else
			{
				if ( it->second == input )
					return { true, sym_map };
				else
					return { false, {} };
			}
		}
		// If input is a variable and target is an expression.
		//
		else if ( input.is_variable() )
		{
			// If special functor:
			//
			if ( target.fn->function == "bcntN" &&
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
						return { false , {} };

					int64_t value_a = ( ( bit_count + exp_out->value->i64 ) % bit_count );
					int64_t value_b = ( ( bit_count + sign * input.value->i64 ) % bit_count );
					if ( value_a == value_b )
						return { true, sym_map };
					else
						return { false, {} };
				}
				// If unknown variable, it's asking for normalized form:
				//
				else
				{
					// Skip if already normalized
					//
					int64_t value = sign * input.value->i64;
					if ( 0 <= value && value < bit_count )
						return { false, {} };

					// Write normalized value and indicate success.
					//
					*exp_out = variable( ( ( bit_count + value ) % bit_count ), op_size );
					return { true, sym_map_new };
				}
			}
			else if ( target.fn->function == "bmask" &&
					  input.is_constant() )
			{
				// Find which variable we're calculating this for.
				// - Referencing unknown variable in simplification condition if assert fail raises.
				//
				auto it = sym_map.find( *target[ 0 ].value );
				if ( it == sym_map.end() )
					return { false, {} };	// TODO????
				fassert( it != sym_map.end() );

				// Calculate number of bits in the variable.
				//
				int8_t bit_count = it->second.size() * 8;
				fassert( bit_count != 0 );

				// Check if it matches.
				//
				uint64_t bit_mask = ~0ull >> ( 64 - bit_count );
				if ( ( input.value->u64 & bit_mask ) == bit_mask )
					return { true, sym_map };
			}
			else if ( target.fn->function == "new" &&
					  input.is_constant() )
			{
				// Find which variable we're calculating this for.
				// - Referencing unknown variable in simplification condition if assert fail raises.
				//
				auto it = sym_map.find( *target[ 0 ].value );
				if ( it == sym_map.end() )
					return { false, {} };	// TODO????
				fassert( it != sym_map.end() );

				// Calculate number of bits in the variable.
				//
				int8_t bit_count = it->second.size() * 8;
				fassert( bit_count != 0 );

				// Check if it is indeed a valid mask.
				//
				int8_t new_bit_count = 0;
				switch ( input.value->u64 )
				{
					case 0xFF:					new_bit_count = 8;  break;
					case 0xFFFF:				new_bit_count = 16; break;
					case 0xFFFFFFFF:			new_bit_count = 32; break;
					case 0xFFFFFFFFFFFFFFFF:	new_bit_count = 64; break;
					default:					return { false, {} };
				}

				// Write the new variable.
				//
				symbol_map sym_map_new = sym_map; 
				expression& exp_out = sym_map_new[ *target[ 1 ].value ];
				fassert( !exp_out.is_valid() );

				// No-operation, if resizing to larger value.
				//
				if ( new_bit_count >= bit_count )
				{
					exp_out = it->second;
				}
				// If constant, resize right now.
				//
				else if( it->second.is_constant() )
				{
					uint64_t bit_mask = ~0ull >> ( 64 - new_bit_count );
					exp_out = variable( it->second.value->u64 & bit_mask, new_bit_count / 8 );
				}
				// Else, insert new.
				//
				else
				{
#if SYMEX_IMPLICIT_RESIZE
					exp_out = it->second;
					exp_out.resize( new_bit_count / 8 );
#else
					exp_out = rules::resize( it->second, variable( new_bit_count / 8, new_bit_count / 8 ) );
#endif
				}
				return { true, sym_map_new };
			}
			
			// If constant maps to expression, try remapping 
			// and checking if it evaluates to the same value.
			//
			else if ( input.is_constant() )
			{
				expression copy = target;
				copy.remap_symbols( sym_map );
				if( copy.evaluate() == input.value )
					return { true, sym_map };
			}
			
			return { false, {} };
		}
		// If both are expressions.
		//
		else
		{
			// If operators mismatch:
			//
			if ( input.fn != target.fn )
			{
				return { false, {} };
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
				std::pair<bool, symbol_map> result;
				if ( input.fn->is_unary )
				{
					result = is_equivalent( input[ 0 ], target[ 0 ], sym_map, op_size );
				}
				// If binary operator:
				//
				else
				{
					// Check if operands match, in order:
					//
					result = is_equivalent( input[ 0 ], target[ 0 ], sym_map, op_size );
					if ( result.first ) result = is_equivalent( input[ 1 ], target[ 1 ], result.second, op_size );

					// Otherwise check if operator is commutative and operands match in reverse:
					//
					if ( !result.first && input.fn->commutative == +1 )
					{
						result = is_equivalent( input[ 0 ], target[ 1 ], sym_map, input[ 1 ].size() );
						if ( result.first ) result = is_equivalent( input[ 1 ], target[ 0 ], result.second, op_size );
					}
				}

				// Return the final result.
				//
				if ( result.first )
					return result;
				else
					return { false, {} };
			}
		}
	}

	// Transforms between equivalent expression trees.
	//
	static expression remap_equivalent( const expression& input, const expression& from, const expression& to )
	{
		// Check if equivalent, if not return invalid expression.
		//
		auto [is_equiv, sym_map] = is_equivalent( input, from );
		if ( !is_equiv )
			return {};

		// Remove any remaining bmask's.
		//
		expression new_expression = to;
		std::function<void( expression& )> remap_bmask = [ & ] ( expression& r )
		{
			if ( r.fn && r.fn->function == "bmask" )
			{
				auto it = sym_map.find( *r.operands[ 0 ].value );
				fassert( it != sym_map.end() );
				r = variable( ~0ull >> ( 64 - ( it->second.size() * 8 ) ), it->second.size() );
			}
			for ( auto& op : r.operands )
				remap_bmask( op );
		};
		remap_bmask( new_expression );

		// Remap symbol.
		//
		new_expression.remap_symbols( sym_map );
		return new_expression;
	}
}