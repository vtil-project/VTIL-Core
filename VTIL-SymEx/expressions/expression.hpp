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
#include <vtil/memory>
#include <set>
#include "unique_identifier.hpp"

// Allow expression::reference to be used with expression type directly as operable.
//
namespace vtil::symbolic { struct expression; };
namespace vtil::math { template<> struct resolve_alias<shared_reference<symbolic::expression>> { using type = symbolic::expression; }; };

namespace vtil::symbolic
{
	// Auto simplify state.
	//
	static constexpr bool auto_simplify = true;

	// Expression descriptor.
	//
	struct expression : math::operable<expression>
	{
		using reference = shared_reference<expression>;

		// If symbolic variable, the unique identifier that it maps to,
		//
		unique_identifier uid = {};

		// If operation, identifier of the operator and the sub-expressions for the operands.
		//
		math::operator_id op = math::operator_id::invalid;
		reference lhs = {};
		reference rhs = {};

		// Bit vector
		//
		math::bit_vector result;

		struct state_desc
		{
			// Boolean to determine whether this is a full expression tree or just a variable.
			//
			bool is_variable = false;

			// Arbitrary complexity value that is used as an inverse reward function for simplification, updated by ::initialize(...).
			//
			size_t complexity = 0;

			// Depth of the current expression, updated by ::initialize(...).
			//
			size_t depth = 0;

			// Hash of the expression used by the simplifier cache, updated by ::initialize(...).
			//
			size_t hash;

			// Whether expression was simplified or not and whether it was successful.
			//
			bool simplified = false;
			bool simplify_success = false;
		} state;

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
		expression( T value, uint8_t bit_count = sizeof( T ) * 8 ) : operable( value, bit_count ) { update( false ); }

		// Constructor for symbolic variables.
		//
		expression( const unique_identifier& uid, uint8_t bit_count ) : operable(), uid( uid ) { operable::bit_count = bit_count; state.is_variable = true; update( false ); }

		// Constructor for expressions.
		//
		expression( math::operator_id op, const reference& rhs ) : operable(), op( op ), rhs( rhs ) { update( auto_simplify ); }
		expression( math::operator_id op, reference&& rhs ) : operable(), op( op ), rhs( std::move( rhs ) ) { update( auto_simplify ); }
		expression( const reference& lhs, math::operator_id op, const reference& rhs ) : operable(), op( op ), lhs( lhs ), rhs( rhs ) { update( auto_simplify ); }
		expression( reference&& lhs, math::operator_id op, const reference& rhs) : operable(), op( op ), lhs( std::move( lhs ) ), rhs( rhs ) { update( auto_simplify ); }
		expression( const reference& lhs, math::operator_id op, reference&& rhs ) : operable(), op( op ), lhs( lhs ), rhs( std::move( rhs ) ) { update( auto_simplify ); }
		expression( reference&& lhs, math::operator_id op, reference&& rhs ) : operable(), op( op ), lhs( std::move( lhs ) ), rhs( std::move( rhs ) ) { update( auto_simplify ); }

		// Wrapper around math::descriptor_of()
		//
		const math::operator_desc* get_op_desc() const { return math::descriptor_of( op ); };

		// Helpers to determine the type of the expression.
		//
		bool is_constant() const { return is_known; }
		bool is_variable() const { return state.is_variable; }
		bool is_expression() const { return !is_variable() && op != math::operator_id::invalid; }
		bool is_unary() const { return is_expression() && get_op_desc()->operand_count == 1; }
		bool is_binary() const { return is_expression() && get_op_desc()->operand_count == 2; }
		bool is_valid() const { return is_expression() || ( uid || is_constant()); }

		// Returns the number of constants used in the expression.
		//
		size_t count_constants() const;

		// Returns the number of variables used in the expression.
		//
		size_t count_variables() const;

		// Returns the number of unique variables used in the expression.
		//
		size_t count_unique_variables( std::set<unique_identifier>* visited = nullptr ) const;

		// Initializes the expression state and simplifies itself if requested so.
		//
		void update( bool auto_simplify );

		// Converts to human-readable format.
		//
		std::string to_string() const;

		// Simplifies the expression.
		//
		expression& simplify( bool deep = false, bool discard = false );

		// TODO:
		//
		bool equals( const expression& other ) const;
	};
};