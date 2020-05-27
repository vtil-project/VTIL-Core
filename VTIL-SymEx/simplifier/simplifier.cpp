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
#include "simplifier.hpp"
#include "directives.hpp"
#include "../expressions/expression.hpp"
#include "../directives/transformer.hpp"
#include <vtil/io>

namespace vtil::symbolic
{
	struct join_depth_exception : std::exception
	{
		const char* what() const throw()
		{
			return "Reached the maximum join depth limit.";
		}
	};

	// Simplifier cache and its accessors.
	//
	static thread_local simplifier_cache_t simplifier_cache;

	void purge_simplifier_cache() { simplifier_cache.clear(); }
	simplifier_cache_t& ref_simplifier_cache() { return simplifier_cache; }

	// Attempts to prettify the expression given.
	//
	static void prettify_expression( expression::reference& exp )
	{
		using namespace logger;
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		scope_padding _p( 1 );
		log<CON_CYN>( "[Prettify]  = %s\n", *exp );
#endif

		// Prettify each operand
		//
		auto pexp = +exp;
		for ( auto* op_ptr : { &pexp->lhs, &pexp->rhs } )
		{
			if ( !op_ptr->is_valid() ) continue;
			prettify_expression( *op_ptr );
		}

		// Update the expression.
		//
		pexp->update( false );
		
		// Enumerate each pack descriptor:
		//
		for ( auto& [dir_src, dir_dst] : directive::pack_descriptors )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst, {}, -1 ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_PRP>( "[Pack] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s\n", *exp );
#endif
				exp = exp_new;
				return;
			}
		}

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		log<CON_YLW>( "= %s\n", *exp );
#endif
	}

	// Attempts to simplify the expression given, returns whether the simplification
	// succeeded or not.
	//
	bool simplify_expression( expression::reference& exp, bool pretty, int64_t max_depth )
	{
		using namespace logger;

		if ( max_depth == 0 )
			throw join_depth_exception{};

		// If simplify hint is set, only call prettify if requested and return.
		//
		if ( exp->simplify_hint )
		{
			if ( pretty ) 
				prettify_expression( exp );
			return false;
		}

		// If not an expression, we cannot simplify further.
		//
		if ( !exp->is_expression() || 
			 exp->op == math::operator_id::ucast || 
			 exp->op == math::operator_id::cast )
			return false;

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		// Log the input.
		//
		scope_padding _p( 1 );
		if ( !state::get()->padding ) log( "\n" );
		log( "[Input]  = %s ", *exp );
		log( "(Hash: %s)\n", exp->hash() );
#endif

		// If we resolved a valid cache entry:
		//
		auto cache_it = simplifier_cache.find( ( boxed_expression& ) *exp );
		if ( cache_it != simplifier_cache.end() )
		{
			// Replace with the cached entry, inherit simplification state.
			//
			if ( cache_it->second.first.is_valid() )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_YLW>( "= %s (From cache, Success: %d)\n", *cache_it->second.first, cache_it->second.second );
#endif
				exp = cache_it->second.first;
				return cache_it->second.second;
			}
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
			log<CON_RED>( "Failed as directed by cache...\n" );
#endif
			return false;
		}

		// Otherwise create a new cache entry with {invalid, false} by default.
		//
		cache_it = simplifier_cache.insert( { ( boxed_expression& ) *exp, { {}, false } } ).first;
		auto& [cache_entry, success_flag] = cache_it->second;

		// Simplify operands first if not done already.
		//
		for ( auto* op_ptr : { &exp->lhs, &exp->rhs } )
		{
			// If invalid or is simplified, skip.
			//
			if ( !op_ptr->is_valid() || op_ptr->get()->simplify_hint )
				continue;

			// If we could simplify the operand:
			//
			expression::reference op_ref = *op_ptr;
			if ( simplify_expression( op_ref, false, max_depth - 1 ) )
			{
				// Own the reference and relocate the pointer.
				//
				auto [exp_new, op_new] = exp.own( op_ptr );

				// Update the expression.
				//
				*op_new = op_ref;
				exp_new->update( false );

				// Recurse, and indicate success.
				//
				simplify_expression( exp, pretty, max_depth - 1 );
				exp_new->simplify_hint = true;
				cache_entry = *exp;
				success_flag = true;
				return true;
			}
		}

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		// Log the bit states.
		//
		log( "[Vector] = %s\n", exp->value );
#endif

		// If reduced to a constant, replace it.
		//
		if ( exp->value.is_known() )
		{
			cache_entry = expression{ exp->value.known_one(), exp->value.size() };
			success_flag = true;
			exp = cache_entry;
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
			log<CON_CYN>( "= %s [By evaluation]\n", *exp );
#endif
			return success_flag;
		}

		// Enumerate each universal simplifier:
		//
		for ( auto& [dir_src, dir_dst] : directive::universal_simplifiers )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst, {}, max_depth ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_GRN>( "[Simplify] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s [By simplify directive]\n", *exp_new );
#endif

				// Recurse, set the hint and return the simplified instance.
				//
				simplify_expression( exp_new, pretty, max_depth );
				( +exp_new )->simplify_hint = true;
				cache_entry = exp_new;
				success_flag = true;
				exp = exp_new;
				return success_flag;
			}
		}

		// Enumerate each join descriptor:
		//
		for ( auto& [dir_src, dir_dst] : directive::join_descriptors )
		{
			// Declare the filter.
			//
			expression_filter_t filter;
			
			// If no maximum depth was set:
			//
			if ( max_depth < 0 )
			{
				filter = [ & ] ( auto& exp_new )
				{
					// If complexity was reduced already, pass.
					//
					if ( exp_new->complexity < exp->complexity )
						return true;

					// Save current cache iterator.
					//
					auto it0 = simplifier_cache.end();
					
					// Try simplifying with maximum depth set as expression's
					// depth times two and pass if complexity was reduced.
					//
					try
					{
						simplify_expression( exp_new, false, exp_new->depth * 2 );
						return exp_new->complexity < exp->complexity;
					}
					// If maximum depth was reached, revert any changes to the cache
					// and fail the join directive.
					//
					catch ( join_depth_exception& )
					{
						simplifier_cache.erase( it0, simplifier_cache.end() );
						return false;
					}
				};
			}
			// Else:
			//
			else
			{
				filter = [ & ] ( auto& exp_new )
				{
					// If complexity was reduced already, pass.
					//
					if ( exp_new->complexity < exp->complexity )
						return true;

					// Attempt simplifying with maximum depth decremented by one,
					// fail if complexity was not reduced.
					//
					simplify_expression( exp_new, false, max_depth - 1 );
					return exp_new->complexity < exp->complexity;
				};
			}

			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst, filter, max_depth ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_GRN>( "[Join] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s [By join directive]\n", *exp_new );
				log<CON_YLW>( "Complexity: %lf => %lf\n", exp->complexity, exp_new->complexity );
#endif

				// Recurse, set the hint and return the simplified instance.
				//
				simplify_expression( exp_new, pretty, max_depth - 1 );
				( +exp_new )->simplify_hint = true;
				cache_entry = exp_new;
				success_flag = true;
				exp = exp_new;
				return success_flag;
			}
		}

		// Enumerate each unpack descriptor:
		//
		for ( auto& [dir_src, dir_dst] : directive::unpack_descriptors )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst, 
				 [ & ] ( auto& exp_new ) { return simplify_expression( exp_new, pretty, max_depth - 1 ) && exp_new->complexity < exp->complexity; }, max_depth ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_YLW>( "[Unpack] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s [By unpack directive]\n", *exp_new );
#endif

				// Set the hint and return the simplified instance.
				//
				( +exp_new )->simplify_hint = true;
				cache_entry = exp_new;
				success_flag = true;
				exp = exp_new;
				return success_flag;
			}
		}

		// Prettify the expression if requested.
		//
		if ( pretty )
			prettify_expression( exp );

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		// Log the output.
		//
		log( "= %s\n\n", *exp );
#endif
		return false;
	}
};