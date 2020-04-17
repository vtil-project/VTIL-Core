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
#include "..\simplifier\expression_simplifier.hpp"

namespace vtil::symbolic
{
	static constexpr uint64_t fnv_initial = 0xcbf29ce484222325;
	
	template<typename T>
	static inline void fnv_append( size_t* hash, const T& ref )
	{
		for ( size_t i = 0; i < sizeof( T ); i++ )
			*hash = ( ( ( const uint8_t* ) &ref )[ i ] ^ *hash ) * 0x100000001B3;
	}

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

		if ( is_variable() )
			return visited->find( uid ) == visited->end();

		return ( lhs ? lhs->count_unique_variables( visited ) : 0 ) +
			( rhs ? rhs->count_unique_variables( visited ) : 0 );
	}

	// Updates the expression state and simplifies itself if requested so.
	//
	void expression::update( bool auto_simplify )
	{
		// If transformation:
		//
		if ( is_expression() )
		{
			// Partially evaluate the function.
			//
			result = math::evaluate_partial( op, lhs ? lhs->result : math::bit_vector{ 0 }, rhs->result );
			
			// If no unknown bits and auto simplification is requested:
			//
			if ( result.is_known() && auto_simplify )
			{
				// Replace with constant.
				//
				logger::log<logger::CON_CYN>( "Simplified(%d, %d => %d) %s => %s\n", 
											  lhs ? lhs->result.size() : 0,
											  rhs ? rhs->result.size() : 0,
											  result.size(),
											  to_string(), format::hex( math::__sx64( result.known_one(), result.size() ) ) );
				*this = expression( result.known_one(), result.size() );
				state.simplified = true;
				state.simplify_success = true;
				return;
			}

			// Bit count is equal to the result's bit count.
			//
			bit_count = result.size();
		}
		// If constant/variable, simply represent as bit vector.
		//
		else
		{
			result = is_constant() 
				? math::bit_vector( u64, bit_count ) 
				: math::bit_vector( bit_count );
		}

		// If variable / constant:
		//
		if ( !is_expression() )
		{
			state.complexity = is_constant() ? 1 : 2;
			state.depth = 1;
			state.hash = fnv_initial + ( is_constant() ? u64 : uid.hash );
			fnv_append( &state.hash, is_constant() );
			fnv_append( &state.hash, bit_count );
			state.simplified = true;
		}
		// If transformation of unary operator:
		//
		else if ( is_unary() )
		{
			state.is_variable = false;
			state.complexity = rhs->state.complexity << 1;
			state.depth = rhs->state.depth + 1;
			state.hash = rhs->state.hash;
			fnv_append( &state.hash, state.depth + ( uint8_t ) op );

			// Auto simplify if requested so.
			//
			if ( auto_simplify ) simplify();
		}
		// If transformation of binary operator:
		//
		else if ( is_binary() )
		{
			state.is_variable = false;
			state.complexity = ( lhs->state.complexity + rhs->state.complexity ) << 1;
			state.depth = std::max( lhs->state.depth, rhs->state.depth ) + 1;
			if ( get_op_desc()->is_commutative )
			{
				state.hash = std::max( lhs->state.hash, rhs->state.hash );
				fnv_append( &state.hash, rhs->state.hash ^ lhs->state.hash );
			}
			else
			{
				state.hash = rhs->state.hash;
				fnv_append( &state.hash, lhs->state.hash );
			}
			fnv_append( &state.hash, state.depth + ( uint8_t ) op );

			// Auto simplify if requested so.
			//
			if ( auto_simplify ) simplify();
		}
	}

	// Simplifies the expression.
	//
	expression& expression::simplify( bool deep, bool discard )
	{
		// If discard is set, reset simplification status.
		//
		if ( discard ) state.simplified = false;

		// If already simplified or variable, return.
		//
		if ( is_variable() || state.simplified ) return *this;

		// If deep, simplify each operand first.
		//
		if ( deep )
		{
			if ( lhs ) ( +lhs )->simplify( true, discard );
			if ( rhs ) ( +rhs )->simplify( true, discard );
		}

		// Invoke simplify_expression, save success flag and return.
		//
		state.simplify_success = simplify_expression( *this );
		state.simplified = true;
		return *this;
	}

	// Converts to human-readable format.
	//
	std::string expression::to_string() const
	{
		// Handle constants, invalids and variables.
		// -- TODO: Fix variable case, small hack for now
		//
		if ( is_constant() )      return format::hex( i64 );
		if ( !is_valid() )        return "NULL";
		if ( is_variable() )      return format::str( "%s:%d", ( const char* ) uid.ptr, bit_count );

		// Redirect to operator descriptor.
		//
		return get_op_desc()->to_string( lhs ? lhs->to_string() : "", rhs->to_string() );
	}
};
