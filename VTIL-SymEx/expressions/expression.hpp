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
#pragma once
#include <vtil/math>
#include <vtil/utility>
#include <set>
#include "unique_identifier.hpp"

// Allow expression::reference to be used with expression type directly as operable.
//
namespace vtil::symbolic { struct expression; };
namespace vtil::math { template<> struct resolve_alias<shared_reference<symbolic::expression>> { using type = symbolic::expression; }; };

namespace vtil::symbolic
{
	// Expression descriptor.
	//
	struct expression : math::operable<expression>
	{
		using reference = shared_reference<expression>;

		// If symbolic variable, the unique identifier that it maps to.
		//
		unique_identifier uid = {};

		// If operation, identifier of the operator and the sub-expressions for the operands.
		//
		math::operator_id op = math::operator_id::invalid;
		reference lhs = {};
		reference rhs = {};

		// An arbitrarily defined complexity value that is used as an inverse reward function in simplification.
		//
		double complexity = 0;

		// Depth of the current expression.
		// - If constant or symbolic variable, = 0
		// - Otherwise                         = max(operands...) + 1
		//
		size_t depth = 0;

		// Hash of the expression used by the simplifier cache.
		//
		hash_t hash_value = {};

		// Whether expression passed the simplifier already or not, note that this is a hint and there may 
		// be cases where it already has passed it and this flag was not set. Albeit those cases will most 
		// likely not cause performance issues due to the caching system.
		//
		bool simplify_hint = false;

		// Default constructor and copy/move.
		//
		expression() = default;
		expression( expression&& exp ) = default;
		expression( const expression & exp ) = default;
		expression& operator=( expression&& exp )= default;
		expression& operator=( const expression & exp ) = default;

		// Construct from constants.
		//
		template<typename T = uint64_t, std::enable_if_t<std::is_integral_v<T>, int> = 0>
		expression( T value, bitcnt_t bit_count = sizeof( T ) * 8 ) : operable( value, bit_count ), simplify_hint( true ) { update( false ); }

		// Constructor for symbolic variables.
		//
		expression( const unique_identifier& uid, bitcnt_t bit_count ) : operable(), uid( uid ), simplify_hint( true ) { value = math::bit_vector( bit_count ); update( false ); }

		// Constructor for expressions.
		//
		expression( math::operator_id op, const reference& rhs ) : operable(), op( op ), rhs( rhs ) { update( true ); }
		expression( math::operator_id op, reference&& rhs ) : operable(), op( op ), rhs( std::move( rhs ) ) { update( true ); }
		expression( const reference& lhs, math::operator_id op, const reference& rhs ) : operable(), op( op ), lhs( lhs ), rhs( rhs ) { update( true ); }
		expression( reference&& lhs, math::operator_id op, const reference& rhs) : operable(), op( op ), lhs( std::move( lhs ) ), rhs( rhs ) { update( true ); }
		expression( const reference& lhs, math::operator_id op, reference&& rhs ) : operable(), op( op ), lhs( lhs ), rhs( std::move( rhs ) ) { update( true ); }
		expression( reference&& lhs, math::operator_id op, reference&& rhs ) : operable(), op( op ), lhs( std::move( lhs ) ), rhs( std::move( rhs ) ) { update( true ); }

		// Alternate "constructors" for internal use for the sake of having control over auto-simplification of user-reaching expressions.
		//
		template<typename A>
		static expression make( math::operator_id op, A&& op1 )
		{
			expression exp = {};
			exp.op = op;
			exp.rhs = std::forward<A>( op1 );
			exp.update( false );
			return exp;
		}

		template<typename A, typename B>
		static expression make( A&& op1, math::operator_id op, B&& op2 )
		{
			expression exp = {};
			exp.op = op;
			exp.lhs = std::forward<A>( op1 );
			exp.rhs = std::forward<B>( op2 );
			exp.update( false );
			return exp;
		}

		// Wrapper around math::descriptor_of()
		//
		const math::operator_desc* get_op_desc() const { return math::descriptor_of( op ); };

		// Helpers to determine the type of the expression.
		//
		bool is_variable() const { return uid; }
		bool is_expression() const { return op != math::operator_id::invalid; }
		bool is_unary() const { return is_expression() && get_op_desc()->operand_count == 1; }
		bool is_binary() const { return is_expression() && get_op_desc()->operand_count == 2; }
		bool is_valid() const { return is_expression() || is_variable() || is_constant(); }
		operator bool() const { return is_valid(); }

		// Returns the cached hash value to abide the standard vtil::hashable.
		//
		hash_t hash() const { return hash_value; }

		// Returns the number of constants used in the expression.
		//
		size_t count_constants() const;

		// Returns the number of variables used in the expression.
		//
		size_t count_variables() const;

		// Returns the number of unique variables used in the expression.
		//
		size_t count_unique_variables( std::set<unique_identifier>* visited = nullptr ) const;

		// Updates the expression state.
		//
		expression& update( bool auto_simplify );

		// Converts to human-readable format.
		//
		std::string to_string() const;

		// Resizes the expression, if not constant, expression::resize will try to propagate 
		// the operation as deep as possible.
		//
		expression& resize( bitcnt_t new_size, bool signed_cast = false );

		// Simplifies and optionally prettifies the expression.
		//
		expression& simplify( bool prettify = false );

		// Returns whether the given expression is identical to the current instance.
		// - Note: basic comparison opeators should not be overloaded since expression is of type
		//         math::operable and that would create multiple meanings.
		//
		bool is_identical( const expression& other ) const;

		// Returns whether the given expression is equivalent to the current instance.
		// - This routine tries to match the simplified forms whereas ::is_identical will try to 
		//   match the operators operands and uids one to one.
		//
		bool equals( const expression& other ) const;

		// Enumerates the whole tree.
		//
		template<typename T>
		const expression& enumerate( const T& fn, bool bottom = false ) const
		{
			if ( bottom )
			{
				if ( lhs ) lhs->enumerate( fn, bottom );
				if ( rhs ) rhs->enumerate( fn, bottom );
				fn( *this );
			}
			else
			{
				fn( *this );
				if ( lhs ) lhs->enumerate( fn, bottom );
				if ( rhs ) rhs->enumerate( fn, bottom );
			}
			return *this;
		}

		// Transforms the whole tree according to the functor.
		//
		template<typename T>
		expression& transform( const T& fn, bool bottom = true, bool auto_simplify = true )
		{
			if ( bottom )
			{
				if ( rhs ) ( +rhs )->transform( fn, bottom, auto_simplify );
				if ( lhs ) ( +lhs )->transform( fn, bottom, auto_simplify );
				update( auto_simplify );
				fn( *this );
				update( auto_simplify );
			}
			else
			{
				fn( *this );
				update( auto_simplify );
				if ( rhs ) ( +rhs )->transform( fn, bottom, auto_simplify );
				if ( lhs ) ( +lhs )->transform( fn, bottom, auto_simplify );
				update( auto_simplify );
			}
			return *this;
		}

		// Simple way to invoke copy constructor using a pointer.
		//
		expression clone() const { return *this; }
	};

	// Boxed expression solves the aforementioned problem by creating a type that can be 
	// used for the storage of an expression in a way that it is meant to be comparable.
	//
	struct boxed_expression : expression 
	{
		using reference = shared_reference<boxed_expression>;

		// Gently wrap around expression.
		//
		boxed_expression() = default;
		boxed_expression( expression&& o ) : expression( std::move( o ) ) {};
		boxed_expression( const expression& o ) : expression( o ) {};
		boxed_expression( boxed_expression&& o ) = default;
		boxed_expression( const boxed_expression& o ) = default;
		boxed_expression& operator=( boxed_expression&& o ) = default;
		boxed_expression& operator=( const boxed_expression& o ) = default;

		// Explicit function to decay back to expression type.
		//
		expression& decay() { return *this; }
		const expression& decay() const { return *this; }

		// Implement comparison operators.
		//
		bool operator==( const boxed_expression& o ) const { return is_identical( o ); }
		bool operator!=( const boxed_expression& o ) const { return !is_identical( o ); }
		bool operator<( const boxed_expression& o ) const { return hash() < o.hash(); }
	};
};