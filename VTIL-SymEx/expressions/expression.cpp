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
// 3. Neither the name of VTIL Project nor the names of its contributors
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.   
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
	expression& expression::resize( bitcnt_t new_size, bool signed_cast, bool no_explicit )
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
		}

		// If expression is lazy, delay it.
		//
		if ( is_lazy )
		{
			if ( is_constant() )
			{
				value = value.resize( new_size, signed_cast );
				update( false );
			}
			else
			{
				if ( no_explicit ) return *this;
				if ( signed_cast )
					*this = __cast( *this, new_size );
				else
					*this = __ucast( *this, new_size );
			}
			return *this;
		}

		switch ( op )
		{
			// If constant resize the value, if variable apply the operation as is.
			// 
			case math::operator_id::invalid:
				if ( is_constant() )
				{
					value = value.resize( new_size, signed_cast );
					update( false );
				}
				else
				{
					if ( no_explicit ) return *this;
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
					if ( no_explicit ) return *this;
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
					if ( no_explicit ) return *this;
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
					lhs.resize( new_size, false );
					update( false );
					break;
				}
			case math::operator_id::shift_right:
				// If we're zero-extending the result:
				//
				if( !signed_cast && new_size > value.size() )
				{
					lhs = std::move( lhs ).resize( new_size, false ); 
					update( false ); 
				}
				// Otherwise nothing else to do.
				//
				else
				{
					if ( no_explicit ) return *this;
					if ( signed_cast )
						*this = __cast( *this, new_size );
					else
						*this = __ucast( *this, new_size );
				}
				break;

			// If not:
			//
			case math::operator_id::bitwise_not:
				if ( !signed_cast )
				{
					// If shrinking, just resize.
					//
					if ( new_size < value.size() )
					{
						( +rhs )->resize( new_size, false );
						update( false );
					}
					// If extending:
					//
					else
					{
						uint64_t rhs_mask = value.known_one() | value.unknown_mask();
						auto rhs_v = std::move( rhs );
						*this = ( ~( rhs_v.resize( new_size, false ) ) ) & expression{ rhs_mask, new_size };
					}
				}
				else
				{
					if ( no_explicit ) return *this;
					*this = __cast( *this, new_size );
				}
				break;

			// If basic unsigned operation, unsigned cast both sides if requested type is also unsigned.
			//
			case math::operator_id::bitwise_and:
			case math::operator_id::bitwise_or:
			case math::operator_id::bitwise_xor:
			case math::operator_id::umultiply:
			case math::operator_id::udivide:
			case math::operator_id::uremainder:
			case math::operator_id::umax_value:
			case math::operator_id::umin_value:
				if ( !signed_cast )
				{
					// If shrinking and is division-related:
					//
					if ( new_size < value.size() && ( op == math::operator_id::udivide || op == math::operator_id::uremainder ))
					{
						if ( no_explicit ) return *this;
						*this = __ucast( *this, new_size );
					}
					else
					{
						if ( lhs ) lhs.resize( new_size, false );
						rhs.resize( new_size, false );
						update( false );
					}
				}
				else
				{
					if ( no_explicit ) return *this;
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
					if ( lhs ) lhs.resize( new_size, true );
					rhs.resize( new_size, true );
					update( false );
				}
				else
				{
					// If shrinking and is not division-related:
					//
					if ( new_size < value.size() && op != math::operator_id::divide && op != math::operator_id::remainder )
					{
						if ( lhs ) lhs.resize( new_size, false );
						rhs.resize( new_size, false );
						update( false );
					}
					else
					{
						if ( no_explicit ) return *this;
						*this = __ucast( *this, new_size );
					}
				}
				break;

			// If casting the result of an unsigned cast:
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
						if ( no_explicit ) return *this;
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
					return update( false );
				}
				break;

			// If casting the result of a signed cast:
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
					return update( false );
				}
				// Else, convert to unsigned cast since top bits will be zero.
				//
				else
				{
					if ( no_explicit ) return *this;
					*this = __ucast( *this, new_size );
				}
				break;

			// Redirect to conditional output since zx 0 == sx 0.
			//
			case math::operator_id::value_if:
				if ( rhs.size() != new_size )
				{
					rhs.resize( new_size, false );
					update( false );
				}
				break;

			// If no handler found:
			//
			default:
				if ( no_explicit ) return *this;
				if ( signed_cast )
					*this = __cast( *this, new_size );
				else
					*this = __ucast( *this, new_size );
				break;
		}

		simplify();
		return *this;
	}

	// Updates the expression state.
	//
	expression& expression::update( bool auto_simplify )
	{
		// Propagate lazyness.
		//
		if ( ( lhs && lhs->is_lazy ) ||
			 ( rhs && rhs->is_lazy ) )
		{
			auto_simplify = false;
			is_lazy = true;
		}

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
				dassert( is_variable() );

				// Assign the constant complexity value.
				//
				complexity = 128;

				// Hash is made up of UID's hash and the number of bits.
				//
				hash_value = make_hash( uid.hash(), ( uint8_t ) value.size() );
			}

			// Set the signature.
			//
			signature = { value };

			// Set simplification state.
			//
			simplify_hint = true;
		}
		else
		{
			dassert( is_expression() );

			// If unary operator:
			//
			const math::operator_desc& desc = get_op_desc();
			if ( desc.operand_count == 1 )
			{
				// Partially evaluate the expression.
				//
				value = math::evaluate_partial( op, {}, rhs->value );

				// Speculative simplification, if value is known replace with a constant, this 
				// is a major performance boost with lazy expressions as child copies and large 
				// destruction chains are completely avoided. Lazy expressions are meant to
				// delay complex simplification rather than block all simplification so this
				// step is totally fine. [1]
				//
				if ( ( is_lazy || auto_simplify ) && value.is_known() )
				{
					lhs = {}; rhs = {};
					op = math::operator_id::invalid;
					is_lazy = false;
					return update( false );
				}

				// Calculate base complexity and the depth.
				//
				depth = rhs->depth + 1;
				complexity = rhs->complexity * 2;
				dassert( complexity != 0 );
				
				// Begin hash as rhs.
				//
				hash_value = rhs->hash();
			}
			// If binary operator:
			//
			else
			{
				dassert( desc.operand_count == 2 );

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

				// Speculative simplification, see [1].
				//
				if ( ( is_lazy || auto_simplify ) && value.is_known() )
				{
					lhs = {}; rhs = {};
					op = math::operator_id::invalid;
					is_lazy = false;
					return update( false );
				}

				// Handle size mismatches.
				//
				const auto optimistic_size = [ ] ( symbolic::expression::reference& lhs,
												   symbolic::expression::reference& rhs )
				{

					bitcnt_t op_size = lhs->size();
					if ( ( op_size < rhs->size() && math::msb( ~rhs->value.known_zero() ) > op_size ) ||
						 ( op_size > rhs->size() && math::msb( ~lhs->value.known_zero() ) < rhs->size() ) )
						op_size = rhs->size();
					return op_size;
				};

				switch ( op )
				{
					case math::operator_id::bitwise_and:
					case math::operator_id::bitwise_or:
					case math::operator_id::bitwise_xor:
					case math::operator_id::umultiply_high:
					case math::operator_id::udivide:
					case math::operator_id::uremainder:
					case math::operator_id::umax_value:
					case math::operator_id::umin_value:
					{
						lhs.resize( value.size(), false );
						rhs.resize( value.size(), false );
						break;
					}
					case math::operator_id::multiply_high:
					case math::operator_id::multiply:
					case math::operator_id::divide:
					case math::operator_id::remainder:
					case math::operator_id::add:
					case math::operator_id::subtract:
					case math::operator_id::max_value:
					case math::operator_id::min_value:
					{
						lhs.resize( value.size(), true );
						rhs.resize( value.size(), true );
						break;
					}
					case math::operator_id::ugreater:
					case math::operator_id::ugreater_eq:
					case math::operator_id::uless_eq:
					case math::operator_id::uless:
					{
						bitcnt_t op_size = optimistic_size( lhs, rhs );
						lhs.resize( op_size, false );
						rhs.resize( op_size, false );
						break;
					}
					case math::operator_id::greater:
					case math::operator_id::greater_eq:
					case math::operator_id::less_eq:
					case math::operator_id::less:
					case math::operator_id::equal:
					case math::operator_id::not_equal:
					{
						bitcnt_t op_size = optimistic_size( lhs, rhs );
						lhs.resize( op_size, true );
						rhs.resize( op_size, true );
						break;
					}

					// Convert unsigned multiply to signed multiply.
					//
					case math::operator_id::umultiply:
					{
						lhs.resize( value.size(), true );
						rhs.resize( value.size(), true );
						op = math::operator_id::multiply;
						break;
					}

					// Convert unsigned compare to signed compare.
					//
					case math::operator_id::uequal:
					case math::operator_id::unot_equal:
					{
						bitcnt_t op_size = optimistic_size( lhs, rhs );
						lhs.resize( op_size, false );
						rhs.resize( op_size, false );
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
				dassert( complexity != 0 );

				// Multiply with operator complexity coefficient.
				//
				complexity *= desc.complexity_coeff;

				// Begin hash as combine(op#1, op#2), make it unordered if operator is commutative.
				//
				hash_value = desc.is_commutative ? combine_unordered_hash( lhs->hash(), rhs->hash() ) : combine_hash( lhs->hash(), rhs->hash() );
			}

			// Set the signature.
			//
			if( lhs ) signature = { lhs->signature, op, rhs->signature };
			else      signature = {                 op, rhs->signature };

			// Append depth, size, and operator information to the hash.
			//
			hash_value = combine_hash( hash_value, make_hash( op, depth, uint8_t( value.size() ) ) );

			// Punish for mixing bitwise and arithmetic operators.
			//
			for ( auto& operand : { &lhs, &rhs } )
			{
				if ( *operand && operand->get()->is_expression() )
				{
					// Bitwise hint of the descriptor contains +1 or -1 if the operator
					// is strictly bitwise or arithmetic respectively and 0 otherwise.
					// This works since mulitplication between them will only be negative
					// if the hints mismatch.
					//
					complexity *= 1 + math::sgn( operand->get()->get_op_desc().hint_bitwise * desc.hint_bitwise );
				}
			}

			// Reset simplification state since expression was updated.
			//
			simplify_hint = false;
		
			// If auto simplification is relevant, invoke it.
			//
			if ( auto_simplify ) simplify();
		}

		// Clear lazyness from children.
		//
		if ( is_lazy )
		{
			if ( lhs && lhs->is_lazy )
				( +lhs )->is_lazy = false;
			if ( rhs && rhs->is_lazy )
				( +rhs )->is_lazy = false;
		}

		return *this;
	}

	// Simplifies the expression.
	//
	expression& expression::simplify( bool prettify )
	{
		// Reset lazyness.
		//
		is_lazy = false;

		// Skip if no point in simplifying.
		//
		if ( !prettify && simplify_hint )
			return *this;

		// By changing the prototype of simplify_expression from f(expression&) to
		// f(expression::reference&), we gain an important performance benefit that is
		// a significantly less amount of copies made. Cache will also store references 
		// this way and additionally we avoid copying where an operand is being simplified
		// as that can be replaced by a simple swap of shared references.
		//
		reference ref = ( reference&& ) make_local_reference( this );
		simplify_expression( ref, prettify );

		// Set the simplifier hint to indicate skipping further calls to simplify_expression.
		//
		ref->simplify_hint = true;

		// If reference is changed, move from it.
		//
		if ( ref.get() != this )
		{
			if( ref.get_entry()->second.load() == 1 ) operator=( std::move( *ref ) );
			else                                      operator=( *ref );
		}
		return *this;
	}

	// Returns whether the given expression is identical to the current instance.
	//
	static bool is_identical_impl( const expression& self, const expression& other )
	{
		if ( &self == &other ) return true;

		auto report_hash_collision = [ & ] ()
		{
#ifdef _DEBUG
			logger::log( "Hash collision detected!\n" );
			logger::log( "[0]: %s\n", self );
			logger::log( "[1]: %s\n", other );

			if ( make_copy( self ).update( false ).hash() != self.hash() )
				logger::log( "Invalid hash for A\n" );
			else if ( make_copy( other ).update( false ).hash() != other.hash() )
				logger::log( "Invalid hash for B\n" );
#endif
			return false;
		};
		constexpr auto cmp = is_identical_impl;

		// If hash/size mismatches, return false without checking anything.
		//
		if ( self.hash() != other.hash() || self.size() != other.size() )
			return false;

		// If variable, check if the identifiers match.
		//
		if ( self.is_variable() )
			return ( other.is_variable() && self.uid == other.uid ) || report_hash_collision();

		// If constant, check if the constants match.
		//
		if ( self.is_constant() )
			return ( other.is_constant() && self.value == other.value ) || report_hash_collision();

		// If operator is not the same, return false.
		//
		if ( self.op != other.op )
			return report_hash_collision();

		// Resolve operator descriptor, if unary, just compare right hand side.
		//
		const math::operator_desc& desc = self.get_op_desc();
		if ( desc.operand_count == 1 )
			return cmp( *self.rhs, *other.rhs ) || report_hash_collision();

		// If both sides match, return true.
		//
		if ( cmp( *self.lhs, *other.lhs ) && cmp( *self.rhs, *other.rhs ) )
			return true;

		// If not, check in reverse as well if commutative and return the final result.
		//
		return ( desc.is_commutative && cmp( *self.lhs, *other.rhs ) && cmp( *self.rhs, *other.lhs ) ) || report_hash_collision();
	}
	bool expression::is_identical( const expression& other ) const { return is_identical_impl( *this, other ); }

	// Returns whether the given expression is equivalent to the current instance.
	//
	bool expression::equals( const expression& other ) const
	{
		// If identical, return true.
		//
		if ( is_identical( other ) )
			return true;

		// Filter by known bits.
		//
		if ( ( other.known_one() & known_zero() ) ||
			 ( other.known_zero() & known_one() ))
			return false;

		// Fast path: if x values do not match, expressions cannot be equivalent.
		//
		if( xvalues() != other.xvalues() )
			return false;

		// Simplify both expressions.
		//
		expression::reference a = make_local_reference( this );
		expression::reference b = make_local_reference( &other );
		a.simplify();
		b.simplify();

		// Determine the final bitwise hint.
		//
		int8_t a_hint = a->is_expression() ? a->get_op_desc().hint_bitwise : 0;
		int8_t b_hint = b->is_expression() ? b->get_op_desc().hint_bitwise : 0;
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

	// Returns whether the given expression is matching the current instance, if so returns
	// the UID relation table, otherwise returns nullopt.
	//
	using fast_uid_relation_table = stack_vector<std::pair<expression::weak_reference, expression::weak_reference>>;
	static bool match_to_impl( const expression::reference& a, const expression::reference& b, fast_uid_relation_table* tbl, bool same_depth )
	{
		// If identical, try pushing all variables into the table.
		//
		if ( a->is_identical( *b ) )
		{
			bool success = true;
			a.transform( [ & ] ( symbolic::expression_delegate& exp )
			{
				if ( !success || !exp->is_variable() ) 
					return;
				for ( auto& [src, dst] : *tbl )
				{
					if ( exp->uid == src->uid && 
						 exp->uid != dst->uid )
					{
						success = false;
						return;
					}
				}
				tbl->emplace_back( exp.ref, exp.ref );
			}, true, false );
			return success;
		}

		// Check if properties match.
		//
		if ( ( same_depth ? a->signature != b->signature : b->signature.can_match( a->signature ) ) || 
			 ( same_depth ? a->depth != b->depth : a->depth > b->depth ) ||
			 a->op != b->op ||
			 a->size() != b->size() )
			return false;

		// If variable:
		//
		if ( a->is_variable() )
		{
			// Skip if compared expression is not a variable if same depth is set.
			//
			if ( same_depth && !b->is_variable() )
				return false;

			// Check if this UID is already in the table, if so return the result of
			// the comparison of the mapping. Otherwise insert into the table.
			//
			for ( auto& [src, dst] : *tbl )
				if ( src->uid == a->uid )
					return dst->is_identical( *b );
			tbl->emplace_back( a, b );
			return true;
		}

		// If constant, check if the constants match.
		//
		if ( a->is_constant() )
			return b->is_constant() && a->value == b->value;

		// Resolve operator descriptor, if unary, just compare right hand side.
		//
		const math::operator_desc& desc = a->get_op_desc();
		if ( desc.operand_count == 1 )
		{
			size_t prev = tbl->size();
			if ( match_to_impl( a->rhs, b->rhs, tbl, same_depth ) )
				return true;
			tbl->resize( prev );
			return false;
		}

		// If both sides match, return true.
		//
		size_t prev = tbl->size();
		if ( match_to_impl( a->lhs, b->lhs, tbl, same_depth ) &&
			 match_to_impl( a->rhs, b->rhs, tbl, same_depth ) )
			return true;
		tbl->resize( prev );

		// Fail if not commutative.
		//
		if ( !desc.is_commutative ) 
			return false;

		// Check in reverse as well and return the final result.
		//
		prev = tbl->size();
		if ( match_to_impl( a->rhs, b->lhs, tbl, same_depth ) &&
			 match_to_impl( a->lhs, b->rhs, tbl, same_depth ) )
			return true;
		tbl->resize( prev );
		return false;
	}
	std::optional<expression::uid_relation_table> expression::match_to( const expression& other, bool same_depth ) const
	{
		auto a = make_local_reference( this );
		auto b = make_local_reference( &other );

		// If variable, fail if other expression is not a variable of same size.
		//
		if ( is_variable() )
		{
			if ( b->is_variable() && size() == b->size() )
				return a->uid != b->uid ? expression::uid_relation_table{ { a, b } } : expression::uid_relation_table{};
		}
		// Otherwise, create the relation table and call into real implementation.
		//
		else
		{
			fast_uid_relation_table fast_tbl;
			if ( match_to_impl( ( expression::reference& )a, ( expression::reference& )b, &fast_tbl, same_depth ) )
				return expression::uid_relation_table{ fast_tbl.begin(), fast_tbl.end() };
		}
		return std::nullopt;
	}

	// Checks if the expression given is a subexpression of the current one.
	//
	bool expression::contains( const expression& o ) const
	{
		// Depth based traversal fast-path.
		//
		if ( depth < o.depth ) 
			return false;

		// If same depth, redirect to is_identical.
		//
		if ( depth == o.depth )
			return is_identical( o );

		// Check child-nodes where possible.
		//
		return rhs && ( rhs->contains( o ) || ( lhs && lhs->contains( o ) ) );
	}

	// Converts to human-readable format.
	//
	std::string expression::to_string() const
	{
		// Redirect to operator descriptor.
		//
		if ( is_expression() )
			return get_op_desc().to_string( lhs ? lhs->to_string() : "", rhs->to_string() );

		// Handle constants, invalids and variables.
		//
		if ( is_constant() )      return format::hex( value.get<true>().value() );
		if ( is_variable() )      return uid.to_string();
		return "null";
	}

	// Implement some helpers to conditionally copy.
	//
	expression_reference& expression_reference::resize( bitcnt_t new_size, bool signed_cast, bool no_explicit )
	{
		if ( new_size != get()->size() )
			own()->resize( new_size, signed_cast, no_explicit );
		return *this;
	}
	expression_reference expression_reference::resize( bitcnt_t new_size, bool signed_cast, bool no_explicit ) const
	{
		return std::move( make_copy( *this ).resize( new_size, signed_cast, no_explicit ) );
	}
	expression_reference& expression_reference::simplify( bool prettify, bool* out )
	{
		bool simplified;
		if ( is_valid() && ( prettify || !get()->simplify_hint ) )
			simplified = simplify_expression( *this, prettify );
		else
			simplified = false;
		if ( out ) *out = simplified;
		return *this;
	}
	expression_reference expression_reference::simplify( bool prettify, bool* out ) const
	{
		return std::move( make_copy( *this ).simplify( prettify, out ) );
	}
	expression_reference& expression_reference::make_lazy()
	{
		if ( !get()->is_lazy )
			own()->is_lazy = true;
		return *this;
	}
	expression_reference expression_reference::make_lazy() const
	{
		return std::move( make_copy( *this ).make_lazy() );
	}

	// Forward declared redirects for internal use cases.
	//
	hash_t expression_reference::hash() const
	{
		return get()->hash();
	}
	bool expression_reference::is_simple() const
	{
		return get()->simplify_hint;
	}
	void expression_reference::update( bool auto_simplify ) 
	{
		own()->update( auto_simplify );
	}

	// Equivalence check.
	//
	bool expression_reference::equals( const expression& exp ) const { return !is_valid() ? !exp : get()->equals( exp ); }
	bool expression_reference::is_identical( const expression& exp ) const { return !is_valid() ? !exp : get()->is_identical( exp ); }

	// Implemented for sinkhole use.
	//
	bitcnt_t expression_reference::size() const 
	{ 
		return is_valid() ? get()->size() : 0; 
	}

	// Implemented for logger use.
	//
	std::string expression_reference::to_string() const
	{
		return is_valid() ? get()->to_string() : "null";
	}
};
