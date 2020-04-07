#pragma once
#include <tuple>
#include <algorithm>
#include <unordered_map>
#include <numeric>
#include "expression.hpp"
#include "variable.hpp"

namespace vtil::symbolic::rules
{
	// Describes an entry in the rule tables.
	//
	struct rule_entry
	{
		// Number of times this rule entry was used to produce optimal result.
		//
		volatile uint32_t points = 0;

		// Base expression containing symbolic expression tree to match against.
		//
		const expression base_expression;

		// Function that performs any additional checks/processing after initial matching.
		//
		std::function<bool( symbol_map& )> extension = {};

		// Constructors for simple and complex logic.
		//
		rule_entry( expression exp ) : base_expression( exp ) {}
		template<typename T>
		rule_entry( expression exp, T extension ) : base_expression( exp ), extension( extension ) {}
		
		// Basic hash function implementation so we can place it in an unordered map.
		//
		struct hash { size_t operator()( const rule_entry& self ) const { return std::hash<std::string>()( self.base_expression.to_string() ); } };
		bool operator==( const rule_entry& o ) const { return base_expression == o.base_expression; }
	};

	// Symbolic variables used in rule creation:
	//
	static const expression A = { { "α", 0 } };
	static const expression B = { { "β", 0 } };
	static const expression C = { { "λ", 0 } };

	// Special variables:
	//
	static const expression X = { { "Σ", 0 } };
	static const expression Q = { { "Ω", 0 } };
	static const expression V = { { "π", 0 } }; // Does not accept constants.
	static const expression U = { { "μ", 0 } }; // Only accepts constants.

	// Special functions used in rule creation:
	//
	static const auto sx = [ ] ( const expression& a, const expression& b ) { return expression( a, find_opr( "__sx" ), b ); };
	static const auto zx = [ ] ( const expression& a, const expression& b ) { return expression( a, find_opr( "__zx" ), b ); };
	static const auto bmask = [ ] ( const expression& a ) { return expression( find_opr( "__bmask" ), a ); };
	static const auto bcnt = [ ] ( const expression& a ) { return expression( find_opr( "__bcnt" ), a ); };
	static const auto bcntN = [ ] ( const expression& a, const expression& b ) { return expression( a, find_opr( "__bcntN" ), b ); };

	// All simpilfications:
	// - Note! Must not contain ( simplified[simplified[x]] == y ).
	//
	static std::unordered_map<rule_entry, expression, rule_entry::hash> simplified_form =
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
		{ (A>>V)|(A<<(bcnt(A)-V)), A.ror(V) },				// [var shift -> var rotation]
		{ (A<<V)|(A>>(bcnt(A)-V)), A.rol(V) },				//
		{ A.rol(bcntN(Q,A)), A.rol(Q) },					// normalize {imm rotation}
		{ A.ror(bcntN(Q,A)), A.ror(Q) },					//
		{ A>>bcntN(Q,A), {0} },								// noramlize {imm shift}
		{ A<<bcntN(Q,A), {0} },								//
		{ (A<<B)>>B, A&(bmask(A)>>B)},
		{ (A>>B)<<B, A&(bmask(A)<<B)},
		
		// Special extended rules
		//
		{ zx(A,B)>>bcntN(Q,A), {0} },						// take in the real size into account when shifting
		{ sx(A,B)>>bcntN(Q,A), {-1>>Q} },					// take in the real size into account when shifting
		
		{ { { A & U }, [ ] ( symbol_map& sym )				// convert mask to __zx
		{
			uint64_t mask = sym[ *U.value ].evaluate()->get();
			auto& in = sym[ *A.value ];
			auto& out = sym[ *Q.value ];
			switch ( mask )
			{
				case 0:						out = { 0 }; break;
				case 0xFF:					out = { expression( in ).resize( 1 ) }; break;
				case 0xFFFF:				out = { expression( in ).resize( 2 ) }; break;
				case 0xFFFFFFFF:			out = { expression( in ).resize( 4 ) }; break;
				case 0xFFFFFFFFFFFFFFFF:	out = { expression( in ).resize( 8 ) }; break;
				default: return false;
			}
			return true;
		} }, { Q } },

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
		{ 0-A, -A },

		// Simplify AND OR
		//
		{ A&(A|B),	A },
		{ A|(A&B),	A },
		
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
		
		// Prefer SUB over NEG
		//
		{ A+(-B), A-B },

		// ADD to OR
		//
		{ ((~A)&B)+(A&C), ((~A)&B)|(A&C) }
	};

	// All alternate forms:
	// - Note: Both sides should contain the same amount of unknowns.
	//
	static std::unordered_map<rule_entry, std::vector<expression>, rule_entry::hash> alternate_forms =
	{
		// Convert between SUB and ADD
		//
		{ A-B, { A+(-B) }},

		// Convert between bitwise and arithmetic negation
		//
		{ ~A, { -(A+1) } },
		{ -A, { ~(A-1) } },

		// Distribute bitwise operators
		//
		{ ~(A^B), { (~A)^B } },
		{ ~(A^B), { A^(~B) } },
		{ ~(A&B), { (~A)|(~B) } },
		{ ~(A|B), { (~A)&(~B) } },
		{ A&(B|C),{ (A&B)|(A&C) } },
		{ A|(B&C),{ (A|B)&(A|C) } },
		{ A&(B^C),{ (A&B)^(A&C) } },
		{ (A&B)>>C,	{ (A>>C)&(B>>C) } },
		{ (A&B)<<C,	{ (A<<C)&(B<<C) } },
		{ (A|B)>>C,	{ (A>>C)|(B>>C) } },
		{ (A|B)<<C,	{ (A<<C)|(B<<C) } },
		{ (A^B)>>C,	{ (A>>C)^(B>>C) } },
		{ (A^B)<<C,	{ (A<<C)^(B<<C) } },
		{ A^(B|C), {(A&(~(B|C)))|((~A)&(B|C)), (A&(~(C|B)))|((~A)&(C|B))} },
		
		// All commutative laws. 
		// - Certain instances are commented out since only node #0 and node #1 are reversed,
		//   and since they are not of the same type, matcher will apply the commutative law
		//   automatically anyways to match the other.
		//
		{ A+(B+C), { (A+B)+C, (A+C)+B } },
		//{ (A+B)+C, { A+(B+C), B+(A+C) } },
		{ A+(B-C), { (A+B)-C, (A-C)+B } },
		//{ (A-B)+C, { (A-C)-B, A+(C-B) } },
		{ A-(B+C), { (A-B)-C, (A-C)-B } },
		{ (A+B)-C, { (A-C)+B, A+(B-C) } },
		{ A-(B-C), { (A-B)+C, (A+C)-B } },
		{ (A-B)-C, { (A-C)-B, A-(B+C) } },
		{ A|(B|C), { (A|B)|C, (A|C)|B } },
		//{ (A|B)|C, { A|(B|C), B|(A|C) } },
		{ A&(B&C), { (A&B)&C, (A&C)&B } },
		//{ (A&B)&C, { A&(B&C), B&(A&C) } },
		{ A^(B^C), { (A^B)^C, (A^C)^B } },
		//{ (A^B)^C, { A^(B^C), B^(A^C) } },
	};

	// A handy helper that invokes enumerator for each entry in the 
	// given map in the order of points and increments the points
	// and breaks out of the loop if callback returns true.
	//
	template<typename T, typename Z>
	static auto for_each( std::unordered_map<rule_entry, T, rule_entry::hash>& map,
						  const Z& enumerator )
	{
		using iterator_type = typename std::unordered_map<rule_entry, T, rule_entry::hash>::iterator;

		std::vector<iterator_type> ref_vec( map.size() );
		std::iota( ref_vec.begin(), ref_vec.end(), map.begin() );
		std::sort( ref_vec.begin(), ref_vec.end(), [ ] ( const iterator_type& a, const iterator_type& b ) { return a->first.points > b->first.points; } );

		using ret_type = decltype( enumerator( ref_vec[ 0 ]->first, ref_vec[ 0 ]->second ) );

		if constexpr ( std::is_same_v<ret_type, void> )
		{
			for ( auto& it : ref_vec )
				enumerator( it->first, it->second );
		}
		else
		{
			for ( auto& it : ref_vec )
			{
				if ( enumerator( it->first, it->second ) )
				{
					++( *( volatile uint32_t* ) &it->first.points );
					return true;
				}
			}
			return false;
		}
	}

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
				// Check special conditions:
				//
				if ( target.value->uid == V.value->uid && input.is_constant() )
					return {};
				if ( target.value->uid == U.value->uid && !input.is_constant() )
					return {};
				
				symbol_map sym_map_new = sym_map;
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
	template<bool bcnt_strict = true>
	static std::optional<symbol_map> match( const expression& input, const rule_entry& rule )
	{
		// All variables should be of the same size.
		//
		fassert( input.is_normalized() );

		// Check if equivalent, if not return invalid expression.
		//
		auto sym_map = match<bcnt_strict>( input, rule.base_expression );
		if ( !sym_map )
			return {};
		if ( rule.extension && !rule.extension( *sym_map ) )
			return {};
		return sym_map;
	}

	// Transforms between equivalent expression trees.
	//
	static expression remap( const expression& input, const symbol_map& sym_map, const expression& to )
	{
		// Remap symbol.
		//
		expression new_expression = to;
		new_expression.remap_symbols( sym_map );

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

	template<bool bcnt_strict = true>
	static std::optional<expression> apply( const expression& input, const rule_entry& rule, const expression& target )
	{
		auto sym_map = match<bcnt_strict>( input, rule );
		if ( !sym_map )
			return {};
		return remap( input, sym_map.value(), target );
	}
}