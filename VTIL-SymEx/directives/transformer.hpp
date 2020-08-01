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
#include "fast_matcher.hpp"
#include "../expressions/expression.hpp"

namespace vtil::symbolic
{
	// Translates the given directive into an expression (of size given) using the symbol table.
	//
	expression::reference translate( const directive::symbol_table_t& sym,
                                     const directive::instance* dir,
                                     bitcnt_t bit_cnt );

	// Attempts to transform the expression in form A to form B as indicated by the directives, 
	// and returns the first instance that matches query.
	//
	template<typename... Tx>
	static expression::reference transform( expression::weak_reference exp,
                                            const directive::instance* from, const directive::instance* to,
											Tx&&... filters )
	{
		using namespace logger;

		// Fast path: check if signature matches.
		//
		dassert( 0 < exp->size() && exp->size() <= 64 );
		if ( !exp->signature.can_match( from->signatures[ exp->size() - 1 ] ) )
			return {};

		// Match the expresison.
		//
		stack_vector<directive::symbol_table_t, 8> results;
		if ( !directive::fast_match( &results, from, exp ) ) 
			return {};

		// For each possible match:
		//
		for ( auto& match : results )
		{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
			// Log the translation.
			//
			log<CON_BLU>( "Translating [%s] => [%s]:\n", *from, *to );
			from->enum_variables( [ & ] ( const instance& ins )
			{
				log<CON_BLU>( "            %s: %s\n", ins.id, *match.translate( ins ) );
			} );
#endif

			// If we could translate the directive:
			//
			if ( auto exp_new = translate( match, to, exp->size() ) )
			{
				// If it passes through the filter:
				//
				if ( ( filters( exp_new ) && ... ) )
				{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
					// Log state and return the expression.
					//
					log<CON_GRN>( "Success.\n" );
#endif
					// Make sure the size matches.
					//
					if ( exp_new->size() != exp->size() )
					{
						// Auto fix if constant:
						//
						if ( exp_new->is_constant() )
						{
							exp_new = { *exp_new->value.get(), exp->size() };
						}
						else
						{
							log( "\n" );
							log<CON_RED>( "Input  (%d bits):   %s\n", exp->size(), exp->to_string() );
							log<CON_RED>( "Output (%d bits):   %s\n", exp_new->size(), exp_new->to_string() );
							error( "Directive '%s' => '%s' left the simplifier unbalanced.", from->to_string(), to->to_string() );
						}
					}

					return exp_new;
				}

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				// Log state.
				//
				log<CON_RED>( "Rejected by filter (Complexity: %lf vs %lf).\n", exp_new->complexity, exp->complexity );
#endif
			}
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
			// Otherwise, log state.
			//
			else
			{
				log<CON_RED>( "Rejected by directive.\n" );
			}
#endif
		}

		// Indicate failure with null reference.
		//
		return {};
	}
};