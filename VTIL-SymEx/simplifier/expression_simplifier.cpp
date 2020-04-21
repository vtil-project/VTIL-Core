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
#include "expression_simplifier.hpp"
#include "..\expressions\expression.hpp"
#include "..\directives\directive.hpp"
#include "simplifier_directives.hpp"
#include "..\directives\match_directive.hpp"
#include <vtil/io>
#include <map>

namespace vtil::symbolic
{
	static bool simplify_verbose = false;
	static bool prettify_verbose = false;
	static thread_local std::unordered_map<size_t, std::pair<expression::reference, bool>> simplifier_cache;

	std::string to_base_exp( directive::symbol_table& sym, const expression::reference& exp, int depth = 0 )
	{
		using namespace logger;

		if ( exp->is_variable() || ( !exp->is_constant() && depth > 1 ) )
		{
			for ( auto& pair : sym.variable_map )
				if ( pair.second->equals( *exp ) )
					return pair.first;

			directive::instance::reference r;
			switch ( sym.variable_map.size() )
			{
				case 0: r = directive::A; break;
				case 1: r = directive::B; break;
				case 2: r = directive::C; break;
				case 3: r = directive::D; break;
				default:
					unreachable();
			}

			fassert( sym.add( r, exp ) );
			return r->id;
		}

		scope_verbosity v( depth == 0 );

		if ( exp->is_binary() )
		{
			std::string lhs = to_base_exp( sym, exp->lhs, depth + 1 );
			std::string rhs = to_base_exp( sym, exp->rhs, depth + 1 );

			auto desc = exp->get_op_desc();
			if ( desc->symbol )
			{
				log<CON_BLU>( "(%s", lhs );
				if ( depth == 0 )
					log<CON_RED>( "%s", desc->symbol );
				else
					log<CON_YLW>( "%s", desc->symbol );
				log<CON_BLU>( "%s)", rhs );

				return lhs + desc->symbol + rhs;
			}
			else
			{
				if ( depth == 0 )
					log<CON_RED>( "%s", desc->function_name );
				else
					log<CON_YLW>( "%s", desc->function_name );
				log<CON_BLU>( "(%s, %s)", lhs, rhs );

				return format::str( "%s(%s, %s)", desc->function_name, lhs, rhs );
			}
		}
		else if ( exp->is_unary() )
		{
			std::string rhs = to_base_exp( sym, exp->rhs, depth + 1 );

			auto desc = exp->get_op_desc();
			if ( desc->symbol )
			{
				if ( depth == 0 )
					log<CON_RED>( "%s", desc->symbol );
				else
					log<CON_YLW>( "%s", desc->symbol );
				log<CON_BLU>( "(%s)", rhs );

				return desc->symbol + rhs;
			}
			else
			{
				if ( depth == 0 )
					log<CON_RED>( "%s", desc->function_name );
				else
					log<CON_YLW>( "%s", desc->function_name );
				log<CON_BLU>( "(%s)", rhs );

				return format::str( "%s(%s)", desc->function_name, rhs );
			}
		}
		else
		{
			return format::hex( exp->get<true>().value() );
		}
	}

	bool prettify_expression( expression::reference& exp )
	{
		using namespace logger;
		scope_padding _p( 1 );

		if( prettify_verbose ) log<CON_CYN>( "[Prettify]  = %s\n", exp->to_string() );

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
			if ( auto exp_new = directive::transform( exp, dir_src, dir_dst ) )
			{
				if ( prettify_verbose ) log<CON_PRP>( "[Pack] %s => %s\n", dir_src->to_string(), dir_dst->to_string() );
				if ( prettify_verbose ) log<CON_GRN>( "= %s\n", exp->to_string() );
				exp = exp_new;
				return exp;
			}
		}

		if ( prettify_verbose ) log<CON_YLW>( "= %s\n", exp->to_string() );
		return true;
	}

	bool simplify_expression( expression::reference& exp, bool pretty )
	{
		using namespace logger;

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

		scope_padding _p( 1 );
		if ( simplify_verbose )
		{
			if ( !log_padding ) log( "\n" );
			log( "[Input]  = %s ", exp->to_string() );
			log( "(Hash: 0x%p)\n", exp->hash );

			// DEBUGGGGG
			log( "[SymFr]  = " );
			directive::symbol_table sss;
			to_base_exp( sss, exp );
			log( "\n" );
		}

		// If we resolved a valid cache entry:
		//
		auto cache_it = simplifier_cache.find( exp->hash );
		if ( cache_it != simplifier_cache.end() )
		{
			// Replace with the cached entry, inherit simplification state.
			//
			if ( cache_it->second.first.is_valid() )
			{
				if ( simplify_verbose ) log<CON_YLW>( "= %s (From cache, Success: %d)\n", cache_it->second.first->to_string(), cache_it->second.second );
				exp = cache_it->second.first;
				return cache_it->second.second;
			}
			if ( simplify_verbose ) log<CON_RED>( "Failed as directed by cache...\n" );
			return false;
		}

		// Otherwise create a new cache entry with {invalid, false} by default.
		//
		auto& [cache_entry, success_flag] = simplifier_cache[ exp->hash ];

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
			auto op_ref = *op_ptr;
			if ( simplify_expression( op_ref, false ) )
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
				simplify_expression( exp, pretty );
				exp_new->simplify_hint = true;
				cache_entry = *exp;
				success_flag = true;
				return true;
			}
		}

		// If reduced to a constant, replace it.
		//
		if ( exp->value.is_known() )
		{
			cache_entry = expression{ exp->value.known_one(), exp->value.size() };
			success_flag = true;
			exp = cache_entry;
			if ( simplify_verbose ) log<CON_CYN>( "= %s [By evaluation]\n", exp->to_string() );
			return success_flag;
		}
		else
		{
			if ( simplify_verbose ) log( "[Vector] = %s\n", exp->value.to_string() );
		}

		// Enumerate each universal simplifier:
		//
		for ( auto& [dir_src, dir_dst] : directive::universal_simplifiers )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = directive::transform( exp, dir_src, dir_dst ) )
			{
				if ( simplify_verbose ) log<CON_GRN>( "[Simplify] %s => %s\n", dir_src->to_string(), dir_dst->to_string() );
				if ( simplify_verbose ) log<CON_GRN>( "= %s [By simplify directive]\n", exp_new->to_string() );

				// Recurse, set the hint and return the simplified instance.
				//
				simplify_expression( exp_new, pretty );
				( +exp_new )->simplify_hint = true;
				cache_entry = exp_new;
				success_flag = true;
				exp = exp_new;
				return success_flag;
			}
		}

		// TODO: Not too sure.
		// Heuristic to determine if expression can be simplified any further:
		//uint64_t res_unk = __popcnt64( exp->unknown_mask() );
		//uint64_t in_unk = __popcnt64( ( exp->lhs ? exp->lhs->unknown_mask() : 0 ) | exp->rhs->unknown_mask() );
		//if ( in_unk > res_unk || ( exp->depth > 1 && in_unk == res_unk ) )
		{
			// Enumerate each join descriptor:
			//
			for ( auto& [dir_src, dir_dst] : directive::join_descriptors )
			{
				// If we can transform the expression by the directive set:
				//
				if ( auto exp_new = directive::transform( exp, dir_src, dir_dst ) )
				{
					if ( simplify_verbose ) log<CON_GRN>( "[Join] %s => %s\n", dir_src->to_string(), dir_dst->to_string() );
					if ( simplify_verbose ) log<CON_YLW>( "Src:   %s [Complexity: %lf]\n", exp->to_string(), exp->complexity );
					if ( simplify_verbose ) log<CON_GRN>( "Dst:   %s [Complexity: %lf]\n", exp_new->to_string(), exp_new->complexity );

					// If complexity increased, skip the directive.
					//
					if ( exp_new->complexity >= exp->complexity )
					{
						if ( simplify_verbose ) log<CON_RED>( "Complexity increased, rejecting.\n", exp->complexity, exp_new->complexity, exp->to_string() );
						continue;
					}
					else
					{
						if ( simplify_verbose ) log<CON_GRN>( "= %s [By join directive]\n", exp_new->to_string() );
					}

					// Otherwise set the hint and return the simplified instance.
					//
					simplify_expression( exp_new, pretty );
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
				if ( auto exp_new = directive::transform( exp, dir_src, dir_dst ) )
				{
					if ( simplify_verbose ) log<CON_YLW>( "[Unpack] %s => %s\n", dir_src->to_string(), dir_dst->to_string() );
					if ( !simplify_expression( exp_new, pretty ) || exp_new->complexity >= exp->complexity ) break;
					if ( simplify_verbose ) log<CON_GRN>( "= %s [By unpack directive]\n", exp_new->to_string() );

					// Otherwise set the hint and return the simplified instance.
					//
					( +exp_new )->simplify_hint = true;
					cache_entry = exp_new;
					success_flag = true;
					exp = exp_new;
					return success_flag;
				}
			}
		}

		// Prettify the expression if requested.
		//
		if ( pretty )
			prettify_expression( exp );

		// Detect possible simplification.
		//
		if ( simplify_verbose )
		{
			if ( exp->is_binary() )
			{
				uint64_t max_s = __popcnt64( ( exp->lhs ? exp->lhs->unknown_mask() : 0 ) | exp->rhs->unknown_mask() );
				if ( __popcnt64( exp->unknown_mask() ) < max_s )
					log<CON_RED>( "Possible simplification missed!!!!\n" );
			}
		}

		if ( simplify_verbose )
		{
			log( "= %s\n", exp->to_string() );
			log( "\n" );
		}
		return false;
	}
};