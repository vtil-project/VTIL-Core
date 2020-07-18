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
#pragma once 
#include <functional> 
#include "directive.hpp" 
#include "../expressions/expression.hpp" 
 
namespace vtil::symbolic::directive 
{ 
	// Internal representation of the Variable -> Expression mapping. 
	// 
	struct symbol_table_t
	{ 
		expression::weak_reference lookup_table[ number_of_lookup_indices ];
 
		// Adds the mapping of a variable to an expression. 
		// 
		bool add( const instance* dir, expression::weak_reference exp ) 
		{ 
			// If it's the first time this variable is being used: 
			// 
			if ( !lookup_table[ dir->lookup_index ] ) 
			{ 
				// Check if the matching condition is met. 
				// 
				switch ( dir->mtype ) 
				{ 
					case match_any:                                                                   break; 
					case match_variable:               if ( !exp->is_variable() )   return false;     break; 
					case match_constant:               if ( !exp->is_constant() )   return false;     break; 
					case match_expression:             if ( !exp->is_expression() ) return false;     break; 
					case match_non_constant:           if ( !exp->unknown_mask() )  return false;     break; 
					case match_non_expression:         if ( exp->is_expression() )  return false;     break; 
					default: unreachable(); 
				} 
 
				// Save the mapping of this symbol and return success. 
				// 
				lookup_table[ dir->lookup_index ] = exp; 
				return true; 
			} 
			else 
			{ 
				// Check if saved expression is equivalent, if not fail. 
				// 
				return lookup_table[ dir->lookup_index ]->is_identical( *exp ); 
			} 
		} 
 
		// Translates a variable to the matching expression. 
		// 
		const expression::reference& translate( const instance* dir ) const 
		{ 
			// Assert the looked up type is variable. 
			// 
			fassert( dir->op == math::operator_id::invalid && !dir->is_constant() ); 
 
			// Translate using the lookup table. 
			// 
			return ( const expression::reference& ) lookup_table[ dir->lookup_index ].make_shared();
		}
		const expression::reference& translate( const instance& dir ) const { return translate( &dir ); }
	}; 
 
	// Tries to match the the given expression with the directive and fills the  
	// given container of symbol_table_t's with the list of possible matches. 
	// 
	template<typename T, std::enable_if_t<std::is_same_v<typename T::value_type, symbol_table_t>, int> = 0> 
	static size_t fast_match( T* results, 
							  const instance* dir, 
							  expression::weak_reference exp, 
							  size_t index = 0 ) 
	{ 
		// Initialize the result list if not done already. 
		// 
		size_t size_0 = results->size(); 
		if ( !size_0 ) 
			results->resize( ++size_0 ); 
 
		// If directive is a constant or a variable: 
		// 
		if ( dir->op == math::operator_id::invalid ) 
		{ 
			auto it = results->begin() + index; 
 
			// If directive is a variable: 
			// 
			if ( dir->id ) 
			{ 
				// If we could not add to the table / match the existing entry, erase the iterator off the results. 
				// 
				if ( !it->add( dir, exp ) ) 
					results->erase( it ); 
			} 
			// If directive is a constant: 
			// 
			else 
			{ 
				// If the constants do not match, erase the iterator off the results. 
				// 
				uint64_t mask = math::fill( exp->size() ); 
				if ( !exp->is_constant() || ( exp->value.known_one() & mask ) != ( dir->value.known_one() & mask ) ) 
					results->erase( it ); 
			} 
		} 
		// If directive is an expression and the operators are the same 
		// 
		else if ( exp->op == dir->op ) 
		{ 
			// Resolve operator descriptor, if unary, redirect to the matching of RHS. 
			// 
			const math::operator_desc& desc = exp->get_op_desc(); 
			if ( desc.operand_count == 1 ) 
				return fast_match( results, dir->rhs, exp->rhs, index ); 
 
			// If operator is commutative: 
			// 
			if ( desc.is_commutative ) 
			{ 
				// Save the current table on stack. 
				// 
				symbol_table_t tmp = results->at( index ); 
 
				// Try matching the directive's RHS with expression's RHS. 
				// 
				if ( size_t n = fast_match( results, dir->rhs, exp->rhs, index ) ) 
				{ 
					// For each result produced, try matching the directive's LHS with expression's LHS. 
					// 
					while ( n-- ) 
						fast_match( results, dir->lhs, exp->lhs, index + n ); 
				} 
 
				// Push the saved table into the results and update the iterator. 
				// 
				results->emplace_back( std::move( tmp ) ); 
				index = results->size() - 1; 
 
				// Try matching the directive's LHS with expression's RHS. 
				// 
				if ( size_t n = fast_match( results, dir->lhs, exp->rhs, index ) ) 
				{ 
					// For each result produced, try matching the directive's RHS with expression's LHS. 
					// 
					while ( n-- ) 
						fast_match( results, dir->rhs, exp->lhs, index + n ); 
				} 
			} 
			// If operator is not commutative: 
			// 
			else 
			{ 
				// Try matching the directive's RHS with expression's RHS. 
				// 
				if ( size_t n = fast_match( results, dir->rhs, exp->rhs, index ) ) 
				{ 
					// For each result produced, try matching the directive's LHS with expression's LHS. 
					// 
					while ( n-- ) 
						fast_match( results, dir->lhs, exp->lhs, index + n ); 
				} 
			} 
		} 
		// If operators do not match, erase the iterator off the results. 
		// 
		else 
		{ 
			results->erase( results->begin() + index ); 
		} 
 
		// Calculate and return the number of results. 
		// 
		return ( results->size() + 1 ) - size_0; 
	} 
	template<typename T, std::enable_if_t<std::is_same_v<typename T::value_type, symbol_table_t>, int> = 0>
	static size_t fast_match( T* results, const instance& dir, expression::weak_reference exp, size_t index = 0 ) { return fast_match( results, &dir, exp, index ); }
};