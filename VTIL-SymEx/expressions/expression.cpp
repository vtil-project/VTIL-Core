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
#include "expression.hpp"
#include <vtil/io>
#include "../simplifier/simplifier.hpp"

namespace vtil::symbolic
{
	// Returns the number of constants used in the expression.
	//
	size_t expression::count_constants() const
	{
		if ( is_constant() )
			return 1;
		return ( lhs ? lhs->count_constants() : 0 ) +
			   ( rhs ? rhs->count_constants() : 0 );
	}

	// Returns the number of variables used in the expression.
	//
	size_t expression::count_variables() const
	{
		if ( is_variable() )
			return 1;
		return ( lhs ? lhs->count_variables() : 0 ) +
			   ( rhs ? rhs->count_variables() : 0 );
	}

	// Returns the number of unique variables used in the expression.
	//
	size_t expression::count_unique_variables( std::set<unique_identifier>* visited ) const
	{
		std::set<unique_identifier> tmp;
		if ( !visited ) visited = &tmp;

		if ( is_variable() && visited->find( uid ) == visited->end() )
		{
			visited->insert( uid );
			return 1;
		}
		else
		{
			return ( lhs ? lhs->count_unique_variables( visited ) : 0 ) +
				   ( rhs ? rhs->count_unique_variables( visited ) : 0 );
		}
	}

	// Resizes the expression, if not constant, expression::resize will try to propagate 
	// the operation as deep as possible.
	//
	expression& expression::resize( bitcnt_t new_size, bool signed_cast )
	{
		// If requested size is equal, skip.
		//
		if ( value.size() == new_size ) return *this;

		// Try to convert signed casts into unsigned ones:
		//
		if ( signed_cast )
		{
			// If result is a boolean or is smaller than current value, sign is irrelevant:
			//
			if ( new_size == 1 || new_size < value.size() )
			{
				signed_cast = false;
			}
			// If high bit is known zero:
			//
			else if ( value.at( value.size() - 1 ) == math::bit_state::zero )
			{
				signed_cast = false;
			}
			/*// If high bit is known one:
			//
			else if ( value.at( value.size() - 1 ) == math::bit_state::one )
			{
				// Extend the sign bit.
				//
				uint64_t sign_mask = math::fill( 64, value.size() );

				// Perform unsigned cast.
				//
				resize( new_size, false );

				// Apply the extended sign bit.
				//
				*this = *this | sign_mask;

				// Return the resulting expression.
				//
				return *this;
			}*/
		}

		switch ( op )
		{
			// If constant resize the value, if variable apply the operation as is.
			// 
			case math::operator_id::invalid:
				if ( is_constant() )
				{
					value = value.resize( new_size, signed_cast );
				}
				else
				{
					if ( signed_cast )
						*this = __cast( *this, new_size );
					else
						*this = __ucast( *this, new_size );
				}
				break;

			// If rotation, unpack into two shifts if non-zero constant rotation and operation is not signed:
			//
			case math::operator_id::rotate_left:
				if ( rhs->is_constant() && rhs->known_one() != 0 && !signed_cast )
				{
					auto lhs_v = std::move( lhs );
					auto rhs_v = std::move( rhs );
					*this = ( ( lhs_v << rhs_v ).resize( new_size ) | ( lhs_v >> ( lhs_v->size() - rhs_v ) ).resize( new_size ) );
				}
				else
				{
					if ( signed_cast )
						*this = __cast( *this, new_size );
					else
						*this = __ucast( *this, new_size );
				}
				break;
			case math::operator_id::rotate_right:
				if ( rhs->is_constant() && rhs->known_one() != 0 && !signed_cast )
				{
					auto lhs_v = std::move( lhs );
					auto rhs_v = std::move( rhs );
					*this = ( ( lhs_v >> rhs_v ).resize( new_size ) | ( lhs_v << ( lhs_v->size() - rhs_v ) ).resize( new_size ) );
				}
				else
				{
					if ( signed_cast )
						*this = __cast( *this, new_size );
					else
						*this = __ucast( *this, new_size );
				}
				break;

			// If bitshift, propagate where possible:
			//
			case math::operator_id::shift_left:
				// If we're shrinking the result:
				// - Cannot be handled for shift right.
				//
				if ( new_size < value.size() )
				{
					// Resize shifted expression and break.
					//
					( +lhs )->resize( new_size, false );
					break;
				}
			case math::operator_id::shift_right:
				// If we're zero-extending the result:
				//
				if( !signed_cast && new_size > value.size() )
				{
					// Calculate the original result's mask.
					//
					expression mask = { value.value_mask(), new_size };

					// Resize shifted expression and update it.
					//
					( +lhs )->resize( new_size, false );
					update( true );

					// Mask the result.
					//
					*this = expression::make( *this, math::operator_id::bitwise_and, mask );
				}
				// Otherwise nothing else to do.
				//
				else
				{
					if ( signed_cast )
						*this = __cast( *this, new_size );
					else
						*this = __ucast( *this, new_size );
				}
				break;

			// If basic unsigned operation, unsigned cast both sides if requested type is also unsigned.
			//
			case math::operator_id::bitwise_and:
			case math::operator_id::bitwise_or:
			case math::operator_id::bitwise_xor:
			case math::operator_id::bitwise_not:
			case math::operator_id::umultiply:
			case math::operator_id::udivide:
			case math::operator_id::uremainder:
			case math::operator_id::umax_value:
			case math::operator_id::umin_value:
				if ( !signed_cast )
				{
					if ( lhs && lhs->size() != new_size ) ( +lhs )->resize( new_size, false );
					if ( rhs->size() != new_size ) ( +rhs )->resize( new_size, false );
				}
				else
				{
					*this = __cast( *this, new_size );
				}
				break;
				
			// If basic signed operation, signed cast both sides if requested type is also signed.
			//
			case math::operator_id::multiply:
			case math::operator_id::divide:
			case math::operator_id::remainder:
			case math::operator_id::add:
			case math::operator_id::negate:
			case math::operator_id::subtract:
			case math::operator_id::max_value:
			case math::operator_id::min_value:
				if ( signed_cast )
				{
					if ( lhs && lhs->size() != new_size ) ( +lhs )->resize( new_size, true );
					if ( rhs->size() != new_size ) ( +rhs )->resize( new_size, true );
				}
				else
				{
					*this = __ucast( *this, new_size );
				}
				break;

			// If casting the result of an unsigned cast, just change the parameter.
			//
			case math::operator_id::ucast:
				// If it was shrinked:
				//
				if ( lhs->size() > rhs->get().value() )
				{
					// If sign extension, double cast.
					//
					if ( signed_cast )
					{
						*this = __cast( *this, new_size );
						break;
					}

					// Otherwise mask it and resize.
					//
					auto lhs_v = std::move( lhs );
					auto rhs_v = std::move( rhs );
					*this = ( lhs_v & expression{ math::fill( rhs_v->get<bitcnt_t>().value() ), lhs_v->size() } ).resize( new_size );
				}
				// If sizes match, escape cast operator.
				//
				else if ( lhs->size() == new_size )
				{
					*this = *std::move( lhs );
				}
				// Otherwise upgrade the parameter.
				//
				else
				{
					*+rhs = new_size;
				}
				break;

			// If casting the result of a signed cast, change the parameter if 
			// requested cast is also a signed.
			//
			case math::operator_id::cast:
				// Signed cast should not be used to shrink.
				//
				fassert( lhs->size() <= rhs->get().value() );

				// If sizes match, escape cast operator.
				//
				if ( lhs->size() == new_size )
				{
					*this = *std::move( lhs );
				}
				// Otherwise, if both are signed upgrade the parameter.
				//
				else if ( signed_cast )
				{
					*+rhs = new_size;
				}
				// Else, convert to unsigned cast since top bits will be zero.
				//
				else
				{
					*this = __ucast( *this, new_size );
				}
				break;

			// Redirect to conditional output since zx 0 == sx 0.
			//
			case math::operator_id::value_if:
				( +rhs )->resize( new_size, false );
				break;

			// If no handler found:
			//
			default:
				if ( signed_cast )
					*this = __cast( *this, new_size );
				else
					*this = __ucast( *this, new_size );
				break;
		}

		update( true );
		return *this;
	}


	// Updates the expression state.
	//
	expression& expression::update( bool auto_simplify )
	{
		// If it's not a full expression tree:
		//
		if ( !is_expression() )
		{
			// Reset depth.
			//
			depth = 0;

			// If constant value:
			//
			if ( is_constant() )
			{
				// Punish for each set bit in [min_{msb x + popcnt x}(v, |v|)], in an exponentially decreasing rate.
				//
				int64_t cval = *value.get<true>();
				complexity = sqrt( 1 + std::min( math::msb( cval ) + math::popcnt( cval ), 
								                 math::msb( abs( cval ) ) + math::popcnt( abs( cval ) ) ) );

				// Hash is made up of the bit vector masks and the number of bits.
				//
				hash_value = make_hash( value.known_zero(), value.known_one(), ( uint8_t ) value.size() );
			}
			// If symbolic variable:
			//
			else
			{
				fassert( is_variable() );

				// Assign the constant complexity value.
				//
				complexity = 128;

				// Hash is made up of UID's hash and the number of bits.
				//
				hash_value = make_hash( uid.hash(), ( uint8_t ) value.size() );
			}

			// Set simplification state.
			//
			simplify_hint = true;
		}
		else
		{
			fassert( is_expression() );

			// If unary operator:
			//
			const math::operator_desc* desc = get_op_desc();
			if ( desc->operand_count == 1 )
			{
				// Partially evaluate the expression.
				//
				value = math::evaluate_partial( op, {}, rhs->value );

				// Calculate base complexity and the depth.
				//
				depth = rhs->depth + 1;
				complexity = rhs->complexity * 2;
				fassert( complexity != 0 );
				
				// Begin hash as combine(rhs, rhs).
				//
				hash_value = make_hash( rhs->hash() );
			}
			// If binary operator:
			//
			else
			{
				fassert( desc->operand_count == 2 );

				// If operation is __cast or __ucast, right hand side must always be a constant, propagate 
				// left hand side value and resize as requested.
				//
				if ( op == math::operator_id::ucast || op == math::operator_id::cast )
				{
					value = lhs->value;
					value.resize( rhs->get<uint8_t>().value(), op == math::operator_id::cast );
				}
				// Partially evaluate the expression if not resize.
				//
				else
				{
					value = math::evaluate_partial( op, lhs->value, rhs->value );
				}

				// Handle size mismatches.
				//
				switch ( op )
				{
					case math::operator_id::bitwise_and:
					case math::operator_id::bitwise_or:
					case math::operator_id::bitwise_xor:
					case math::operator_id::umultiply_high:
					case math::operator_id::umultiply:
					case math::operator_id::udivide:
					case math::operator_id::uremainder:
					case math::operator_id::umax_value:
					case math::operator_id::umin_value:
						if ( lhs->size() != value.size() ) ( +lhs )->resize( value.size(), false );
						if ( rhs->size() != value.size() ) ( +rhs )->resize( value.size(), false );
						break;
					case math::operator_id::multiply_high:
					case math::operator_id::multiply:
					case math::operator_id::divide:
					case math::operator_id::remainder:
					case math::operator_id::add:
					case math::operator_id::subtract:
					case math::operator_id::max_value:
					case math::operator_id::min_value:
						if ( lhs->size() != value.size() ) ( +lhs )->resize( value.size(), true );
						if ( rhs->size() != value.size() ) ( +rhs )->resize( value.size(), true );
						break;
					case math::operator_id::ugreater:
					case math::operator_id::ugreater_eq:
					case math::operator_id::uless_eq:
					case math::operator_id::uless:
					{
						bitcnt_t op_size = std::max( lhs->size(), rhs->size() );
						if ( lhs->size() != op_size ) ( +lhs )->resize( op_size, false );
						if ( rhs->size() != op_size ) ( +rhs )->resize( op_size, false );
						break;
					}
					case math::operator_id::greater:
					case math::operator_id::greater_eq:
					case math::operator_id::less_eq:
					case math::operator_id::less:
					case math::operator_id::equal:
					case math::operator_id::not_equal:
					{
						bitcnt_t op_size = std::max( lhs->size(), rhs->size() );
						if ( lhs->size() != op_size ) ( +lhs )->resize( op_size, true );
						if ( rhs->size() != op_size ) ( +rhs )->resize( op_size, true );
						break;
					}

					// Convert unsigned compare to signed compare.
					//
					case math::operator_id::uequal:
					case math::operator_id::unot_equal:
					{
						bitcnt_t op_size = std::max( lhs->size(), rhs->size() );
						if ( lhs->size() != op_size ) ( +lhs )->resize( op_size, false );
						if ( rhs->size() != op_size ) ( +rhs )->resize( op_size, false );
						op = op == math::operator_id::uequal ? math::operator_id::equal
							                                 : math::operator_id::not_equal;
						break;
					}
					default:
						break;
				}

				// Calculate base complexity and the depth.
				//
				depth = std::max( lhs->depth, rhs->depth ) + 1;
				complexity = ( lhs->complexity + rhs->complexity ) * 2;
				fassert( complexity != 0 );

				// If bitshift / rotation, punish additionally.
				//
				if ( op == math::operator_id::shift_left || op == math::operator_id::shift_right ||
					 op == math::operator_id::rotate_left || op == math::operator_id::rotate_right )
					complexity *= 2;

				hash_t operand_hashes[] = { lhs->hash(), rhs->hash() };
				// If operator is commutative, sort the array so that the
				// positioning does not matter.
				//
				if ( desc->is_commutative )
					std::sort( operand_hashes, std::end( operand_hashes ) );
				
				// Begin hash as combine(op#1, op#2).
				//
				hash_value = make_hash( operand_hashes );
			}

			// Append depth, size, and operator information to the hash.
			//
			hash_value = make_hash( hash_value, op, depth, uint8_t( value.size() ) );

			// Punish for mixing bitwise and arithmetic operators.
			//
			for ( auto& operand : { &lhs, &rhs } )
			{
				if ( *operand && operand->reference->is_expression() )
				{
					// Bitwise hint of the descriptor contains +1 or -1 if the operator
					// is strictly bitwise or arithmetic respectively and 0 otherwise.
					// This works since mulitplication between them will only be negative
					// if the hints mismatch.
					//
					complexity *= 1 + math::sgn( operand->reference->get_op_desc()->hint_bitwise * desc->hint_bitwise );
				}
			}
			
			// Reset simplification state since expression was updated.
			//
			simplify_hint = false;
		
			// If auto simplification is relevant, invoke it.
			//
			if ( auto_simplify ) simplify();
		}
		return *this;
	}

	// Simplifies the expression.
	//
	expression& expression::simplify( bool prettify )
	{
		// By changing the prototype of simplify_expression from f(expression&) to
		// f(expression::reference&), we gain an important performance benefit that is
		// a significantly less amount of copies made. Cache will also store references 
		// this way and additionally we avoid copying where an operand is being simplified
		// as that can be replaced by a simple swap of shared references.
		//
		auto ref = make_local_reference( this );
		simplify_expression( ref, prettify );

		// Only thing that we should be careful about is the case expression->simplify(),
		// which is problematic since it is not actually a shared reference, which we can
		// carefully solve with the local reference system (which will assert that, no 
		// references to it was stored on destructor for us) and making sure to copy data
		// if the pointer was replaced.
		//
		if ( &*ref != this ) 
			operator=( *ref );
		else
			fassert( ref.reference.use_count() == 1 );

		// Set the simplifier hint to indicate skipping further calls to simplify_expression.
		//
		simplify_hint = true;
		return *this;
	}

	// Returns whether the given expression is equivalent to the current instance.
	//
	bool expression::equals( const expression& other ) const
	{
		// If identical, return true.
		//
		if ( is_identical( other ) )
			return true;

		// Simplify both expressions.
		//
		expression a = expression{ *this }.simplify();
		expression b = expression{ other }.simplify();

		// Determine the final bitwise hint.
		//
		int8_t a_hint = a.is_expression() ? a.get_op_desc()->hint_bitwise : 0;
		int8_t b_hint = b.is_expression() ? b.get_op_desc()->hint_bitwise : 0;
		int8_t m_hint = a_hint != 0 && b_hint != 0 
			? ( a_hint == 1 && b_hint == 1 ) 
			: ( a_hint != 0 ? a_hint : b_hint );

		// If arithmetic hint, try A-B==0 first and then A^B==0.
		//
		if ( m_hint == +1 )
			return ( a - b ).get().value_or( -1 ) == 0 || 
			       ( a ^ b ).get().value_or( -1 ) == 0;

		// If bitwise or null hint, try A^B==0 first and then A-B==0.
		//
		else
			return ( a ^ b ).get().value_or( -1 ) == 0 || 
			       ( a - b ).get().value_or( -1 ) == 0;
	}

	// Evaluates the expression invoking the callback passed for unknown variables,
	// this avoids copying of the entire tree and any simplifier calls so is preferred
	// over *transform(...).get().
	//
	math::bit_vector expression::evaluate( const eval_lookup_helper_t& lookup ) const
	{
		// If value is known, return as is.
		//
		if ( value.is_known() ) 
			return value;
		
		// If variable:
		//
		if ( is_variable() )
		{
			// If lookup helper passed and succesfully finds the value, use as is.
			//
			if ( auto res = lookup ? lookup( uid ) : std::nullopt; res.has_value() )
				return { *res, size() };
			
			// Otherwise return unknown.
			//
			return value;
		}

		// Try to evaluate the result and return.
		//
		math::bit_vector result = {};
		if ( is_unary() )
			result = math::evaluate_partial( op, {},                      rhs->evaluate( lookup ) );
		else if ( is_binary() )
			result = math::evaluate_partial( op, lhs->evaluate( lookup ), rhs->evaluate( lookup ) );
		return result;
	}

	// Returns whether the given expression is identical to the current instance.
	//
	bool expression::is_identical( const expression& other ) const
	{
		// If hash mismatch, return false without checking anything.
		//
		if ( hash() != other.hash() )
			return false;

		// If operator or the sizes are not the same, return false.
		//
		if ( op != other.op || size() != other.size() )
			return false;

		// If variable, check if the identifiers match.
		//
		if ( is_variable() )
			return other.is_variable() && uid == other.uid;

		// If constant, check if the constants match.
		//
		if ( is_constant() )
			return other.is_constant() && value == other.value;

		// Resolve operator descriptor, if unary, just compare right hand side.
		//
		const math::operator_desc* desc = get_op_desc();
		if ( desc->operand_count == 1 )
			return rhs == other.rhs || rhs->is_identical( *other.rhs );

		// If both sides match, return true.
		//
		if ( ( lhs == other.lhs || lhs->is_identical( *other.lhs ) ) &&
			 ( rhs == other.rhs || rhs->is_identical( *other.rhs ) ))
			return true;

		// If not, check in reverse as well if commutative and return the final result.
		//
		return	desc->is_commutative && 
				( lhs == other.rhs || lhs->is_identical( *other.rhs ) ) &&
				( rhs == other.lhs || rhs->is_identical( *other.lhs ) );
	}

	// Converts to human-readable format.
	//
	std::string expression::to_string() const
	{
		// Redirect to operator descriptor.
		//
		if ( is_expression() )
			return get_op_desc()->to_string( lhs ? lhs->to_string() : "", rhs->to_string() );

		// Handle constants, invalids and variables.
		//
		if ( is_constant() )      return format::hex( value.get<true>().value() );
		if ( is_variable() )      return uid.to_string();
		return "null";
	}
};
