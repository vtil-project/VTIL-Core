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
#include <map>
#include "directive.hpp"
#include "..\expressions\expression.hpp"

namespace vtil::symbolic::directive
{
	// Internal representation of the Variable -> Expression mapping.
	//
	struct symbol_table
	{
		std::map<const char*, expression::reference> variable_map;

		bool add( const instance::reference& dir, const expression::reference& exp )
		{
			// If it's the first time this variable is being used:
			//
			auto it = variable_map.find( dir->id );
			if ( it == variable_map.end() )
			{
				// Check if the matching condition is met.
				//
				switch ( dir->mtype )
				{
					case match_any:                                                                   break;
					case match_variable:               if ( !exp->is_variable()   )   return false;   break;
					case match_constant:               if ( !exp->is_constant()   )   return false;   break;
					case match_expression:             if ( !exp->is_expression() )   return false;   break;
					case match_variable_or_constant:   if (  exp->is_expression() )   return false;   break;
					default: unreachable();
				}

				// Save the mapping of this symbol and return success.
				//
				variable_map[ dir->id ] = exp;
				return true;
			}
			else
			{
				// Check if saved expression is equivalent, if not fail.
				//
				return it->second->equals( *exp );
			}
		}

		expression::reference translate( const instance::reference& dir ) const
		{
			// Lookup the map for the variable
			//
			auto it = variable_map.find( dir->id );

			// Return the saved variable if found or else null reference.
			//
			return it != variable_map.end() ? it->second : expression::reference{};
		}
	};

	// Translates the given directive into an expression (of size given) using the symbol table.
	// - If speculative flag is set, it will either return a dummy reference if the expression could be built,
	//   or a null reference if it would fail.
	//
	expression::reference translate( const symbol_table& sym,
									 const instance::reference& dir,
									 bitcnt_t bit_cnt,
									 bool speculative_condition );

	// Tries to match the the given expression with the directive and fills the symbol table with
	// the variable mapping it would be a valid match, target directive can be passed if the caller
	// requires speculative validation of the translation into another directive. This argument will
	// not be propagated when recursing if it is not a tail call.
	//
	bool match( symbol_table& sym,
				const instance::reference& dir,
				const expression::reference& exp,
				uint8_t bit_cnt,
				const instance::reference& target_directive = {} );

	// Attempts to transform the expression in form A to form B as indicated by the directives.
	//
	expression::reference transform( const expression::reference& exp, const instance::reference& from, const instance::reference& to );
};