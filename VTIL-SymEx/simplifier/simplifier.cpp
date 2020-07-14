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
#include "simplifier.hpp"
#include "directives.hpp"
#include "boolean_directives.hpp"
#include "../expressions/expression.hpp"
#include "../directives/transformer.hpp"
#include <vtil/io>
#include <vtil/utility>

namespace vtil::symbolic
{
	struct join_depth_exception : std::exception
	{
		const char* what() const throw()
		{
			return "Reached the maximum join depth limit.";
		}
	};

	// Implement lookup-table based dynamic tables.
	//
	using static_directive_table_entry =  std::pair<directive::instance,        directive::instance>;
	using dynamic_directive_table_entry = std::pair<const directive::instance*, const directive::instance*>;

	using dynamic_directive_table =      std::vector<dynamic_directive_table_entry>;
	using organized_directive_table =    std::array<dynamic_directive_table, ( size_t ) math::operator_id::max>;

	template<typename T>
	static organized_directive_table build_dynamic_table( const T& container )
	{
		organized_directive_table table;
		for ( auto [table, op] : zip( table, iindices() ) )
			for( auto& directive : container )
				if ( directive.first.op == ( math::operator_id ) op )
					table.emplace_back( &directive.first, &directive.second );
		return table;
	};

	static auto& get_boolean_joiners( math::operator_id op ) { static auto tbl = build_dynamic_table( directive::boolean_joiners ); return tbl[ ( size_t ) op ]; }
	static auto& get_pack_descriptors( math::operator_id op ) { static auto tbl = build_dynamic_table( directive::pack_descriptors ); return tbl[ ( size_t ) op ]; }
	static auto& get_join_descriptors( math::operator_id op ) { static auto tbl = build_dynamic_table( directive::join_descriptors ); return tbl[ ( size_t ) op ]; }
	static auto& get_unpack_descriptors( math::operator_id op ) { static auto tbl = build_dynamic_table( directive::unpack_descriptors ); return tbl[ ( size_t ) op ]; }
	static auto& get_boolean_simplifiers( math::operator_id op ) { static auto boolean_simplifiers = directive::build_boolean_simplifiers(); static auto tbl = build_dynamic_table( boolean_simplifiers ); return tbl[ ( size_t ) op ]; }
	static auto& get_universal_simplifiers( math::operator_id op ) { static auto tbl = build_dynamic_table( directive::universal_simplifiers ); return tbl[ ( size_t ) op ]; }

	// Simplifier cache and its accessors.
	//
	using cache_bucket_t = std::unordered_map<expression::reference, std::pair<expression::reference, bool>, 
		                                      expression::reference::hasher, 
		                                      expression::reference::if_identical                          >;

	static constexpr size_t simplifier_bucket_count = 16;

	struct local_cache_t
	{
		cache_bucket_t main_cache[ simplifier_bucket_count ];
		cache_bucket_t spec_cache[ simplifier_bucket_count ];
		bool spec_cache_enabled = false;
		bitmap<simplifier_bucket_count> spec_cache_dirty;

		void begin_speculative()
		{
			spec_cache_enabled = true;
			spec_cache_dirty = {};
		}
		void join_speculative()
		{
			while ( true )
			{
				size_t n = spec_cache_dirty.find( true );
				if ( n == math::bit_npos ) break;
				spec_cache_dirty.set( n, false );

				auto& main = main_cache[ n ];
				auto& spec = spec_cache[ n ];
				main.insert( std::make_move_iterator( spec.begin() ), std::make_move_iterator( spec.end() ) );
				spec.clear();
			}
			spec_cache_enabled = false;
		}
		void trash_speculative()
		{
			while ( true )
			{
				size_t n = spec_cache_dirty.find( true );
				if ( n == math::bit_npos ) break;
				spec_cache_dirty.set( n, false );

				auto& spec = spec_cache[ n ];
				spec.clear();
			}
			spec_cache_enabled = false;
		}
		std::tuple<expression::reference&, bool&, bool> lookup( const expression::reference& exp )
		{
			size_t bucket_id = ( size_t ) exp->op % simplifier_bucket_count;

			if ( spec_cache_enabled )
			{
				if ( auto it = main_cache[ bucket_id ].find( exp ); it != main_cache[ bucket_id ].end() )
					return { it->second.first, it->second.second, true };

				if ( spec_cache_dirty.blocks[ 0 ] == 0 )
				{
					auto [it, inserted] = main_cache[ bucket_id ].emplace( exp, make_default<std::pair<expression::reference, bool>>() );
					return { it->second.first, it->second.second, !inserted };
				}

				auto [it, inserted] = spec_cache[ bucket_id ].emplace( exp, make_default<std::pair<expression::reference, bool>>() );
				spec_cache_dirty.set( bucket_id, true );
				return { it->second.first, it->second.second, !inserted };
			}

			auto [it, inserted] = main_cache[ bucket_id ].emplace( exp, make_default<std::pair<expression::reference, bool>>() );
			return { it->second.first, it->second.second, !inserted };
		}

		void purge()
		{
			for ( auto& bucket : main_cache )
				bucket.clear();
		}
	};
	static thread_local local_cache_t local_cache;
	void purge_simplifier_cache() { local_cache = {}; }

	// Attempts to prettify the expression given.
	//
	static bool prettify_expression( expression::reference& exp )
	{
		using namespace logger;
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		scope_padding _p( 1 );
		log<CON_CYN>( "[Prettify]  = %s\n", *exp );
#endif

		// Prettify each operand.
		//
		auto pexp = +exp;
		for ( auto* op_ptr : { &pexp->lhs, &pexp->rhs } )
		{
			if ( !op_ptr->is_valid() ) continue;
			
			// If successful, recurse.
			//
			if ( prettify_expression( *op_ptr ) )
			{
				pexp->update( false );
				simplify_expression( exp, true, -1, false );
				return true;
			}
		}

		// Update the expression.
		//
		pexp->update( false );
		
		// Enumerate each pack descriptor:
		//
		for ( auto [dir_src, dir_dst] : get_pack_descriptors( exp->op )  )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst, -1 ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_PRP>( "[Pack] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s\n", *exp );
#endif
				exp = exp_new;
				return true;
			}
		}

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		log<CON_YLW>( "= %s\n", *exp );
#endif
		return false;
	}

	// Checks if the expression can be interpreted as a vector-boolean expression.
	//
	static std::pair<bool, expression::reference> match_boolean_expression( const expression::reference& exp )
	{
		switch ( exp->op )
		{
			// If constant / variable, indicate success and return self if variable:
			//
			case math::operator_id::invalid:
			{
				if ( exp->is_variable() ) return { true, exp };
				else                      return { true, nullptr };
			}

			// If bitwise not, continue from rhs.
			//
			case math::operator_id::bitwise_not:
				return match_boolean_expression( exp->rhs );

			// Bitwise OR/AND/XOR match both sides, if both were succesful
			// and had matching/null UIDs, indicate success.
			//
			case math::operator_id::bitwise_or:
			case math::operator_id::bitwise_and:
			case math::operator_id::bitwise_xor:
			{
				auto [m1, p1] = match_boolean_expression( exp->lhs );
				if ( !m1 ) return { false, nullptr };
				auto [m2, p2] = match_boolean_expression( exp->rhs );
				if ( !m2 ) return { false, nullptr };

				if ( !p2 ) return { true, std::move( p1 ) };
				if ( !p1 ) return { true, std::move( p2 ) };

				if ( p1->uid == p2->uid )
					return { true, std::move( p1 ) };
				else
					return { false, nullptr };
			}

			// Illegal operation, fail.
			//
			default:
				return { false, nullptr };
		}
	}

	// Attempts to normalize a vector-boolean expression into a simpler format.
	//
	static bool simplify_boolean_expression( expression::reference& exp )
	{
		// If it does not match a basic boolean expression, return false.
		//
		auto [is_match, uid_base] = match_boolean_expression( exp );
		if ( !is_match ) return false;

		// Evaluate for both states.
		//
		auto r0 = exp->evaluate( [ & ] ( auto& uid ) { return 0ull; } );
		auto r1 = exp->evaluate( [ & ] ( auto& uid ) { return ~0ull; } );

		// Calculate normal form AND/OR/XOR masks.
		//
		uint64_t and_mask = { ~( r0.known_zero() & r1.known_zero() ) };
		uint64_t or_mask = { r0.known_one() & r1.known_one() };
		uint64_t xor_mask = { r0.known_one() & r1.known_zero() };

		// Apply each mask if not no-op.
		//
		expression::reference&    exp_new = uid_base;
		if ( and_mask != ~0ull )  exp_new = exp_new & expression{ and_mask, exp->size() };
		if ( xor_mask )           exp_new = exp_new ^ expression{ xor_mask, exp->size() };
		if ( or_mask )            exp_new = exp_new | expression{ or_mask,  exp->size() };

		// If complexity was higher or equal, fail.
		//
		if ( exp_new->complexity >= exp->complexity ) return false;
		
		// Apply and return.
		//
		exp = std::move( exp_new );
		return true;
	}

	// Attempts to simplify the expression given, returns whether the simplification
	// succeeded or not.
	//
	bool simplify_expression( expression::reference& exp, bool pretty, int64_t max_depth, bool unpack )
	{
		using namespace logger;

		if ( max_depth == 0 )
			throw join_depth_exception{};

		// Clear lazy if not done.
		//
		if ( exp->is_lazy )
			( +exp )->is_lazy = false;

		// If not an expression, we cannot simplify further.
		//
		if ( !exp->is_expression() )
			return false;

		// If simplify hint is set, only call prettify if requested and return.
		//
		if ( exp->simplify_hint )
		{
			if ( pretty )
				prettify_expression( exp );
			return false;
		}

		// If expression has known value, return as is.
		//
		if ( exp->value.is_known() )
		{
			exp = expression{ exp->value.known_one(), exp->value.size() };
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
			log<CON_CYN>( "= %s [By evaluation]\n", *exp );
#endif
			return true;
		}

#if VTIL_SYMEX_SIMPLIFY_VERBOSE
		// Log the input.
		//
		scope_padding _p( 1 );
		if ( !state::get()->padding ) log( "\n" );
		log( "[Input]  = %s ", *exp );
		log( "(Hash: %s)\n", exp->hash() );
#endif

		// Lookup the expression in the cache.
		//
		auto& lcache = local_cache;
		auto [cache_entry, success_flag, found] = lcache.lookup( exp );

		// If we resolved a valid cache entry:
		//
		if ( found )
		{
			// Replace with the cached entry if simplifies.
			//
			if ( cache_entry && success_flag )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_YLW>( "= %s (From cache, Success: %d)\n", *cache_entry, success_flag );
#endif
				exp = cache_entry;
				return true;
			}
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
			log<CON_RED>( "Failed as directed by cache...\n" );
#endif
			return false;
		}

		// If trying to simplify resizing:
		//
		if ( exp->op == math::operator_id::ucast ||
			 exp->op == math::operator_id::cast )
		{
			// Simplify left hand side with the exact same arguments.
			//
			expression::reference exp_new = exp->lhs;
			bool simplified = simplify_expression( exp_new, pretty, max_depth - 1, unpack );
			bitcnt_t new_size = math::narrow_cast<bitcnt_t>( *exp->rhs->get() );

			// Invoke resize with failure on explicit cast:
			//
			exp_new.resize( new_size, exp->op == math::operator_id::cast, true );

			// If implicit resize failed:
			//
			if ( exp_new->size() != new_size )
			{
				// If operand was simplified, indicate success.
				//
				if ( simplified )
				{
					( +exp )->lhs = exp_new;
					( +exp )->update( false );
					success_flag = true;
				}
			}
			else
			{
				// If operand was simplified or if the complexity reduced, indicate success. 
				//
				if ( simplified || exp_new->complexity < exp->complexity )
				{
					exp = exp_new;
					success_flag = true;
				}
			}

			exp->simplify_hint = true;
			cache_entry = exp;
			return success_flag;
		}

		// If expression matches a basic boolean expression, simplify through that first:
		//
		if ( simplify_boolean_expression( exp ) )
		{
			// Recurse, and indicate success.
			//
			simplify_expression( exp, pretty, max_depth - 1 );
			exp->simplify_hint = true;
			cache_entry = exp;
			success_flag = true;
			return true;
		}

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
				exp->simplify_hint = true;
				cache_entry = exp;
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
		for ( auto [dir_src, dir_dst] : get_universal_simplifiers( exp->op ) )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst, max_depth ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_GRN>( "[Simplify] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s [By simplify directive]\n", *exp_new );
#endif
				// Recurse, set the hint and return the simplified instance.
				//
				simplify_expression( exp_new, pretty, max_depth );
				exp_new->simplify_hint = true;
				cache_entry = exp_new;
				if( success_flag = !exp->is_identical( *exp_new ) )
					exp = exp_new;
				return success_flag;
			}
		}

		// If it is a boolean expression:
		//
		if ( exp->size() == 1 )
		{
			// Enumerate each universal simplifier:
			//
			for ( auto [dir_src, dir_dst] : get_boolean_simplifiers( exp->op ) )
			{
				// If we can transform the expression by the directive set:
				//
				if ( auto exp_new = transform( exp, dir_src, dir_dst, max_depth ) )
				{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
					log<CON_GRN>( "[Simplify] %s => %s\n", *dir_src, *dir_dst );
					log<CON_GRN>( "= %s [By simplify directive]\n", *exp_new );
#endif
					// Recurse, set the hint and return the simplified instance.
					//
					simplify_expression( exp_new, pretty, max_depth );
					exp_new->simplify_hint = true;
					cache_entry = exp_new;
					if ( success_flag = !exp->is_identical( *exp_new ) )
						exp = exp_new;
					return success_flag;
				}
			}
		}

		// Declare the filter.
		//
		auto filter = [ &, max_depth ] ( auto& exp_new )
		{
			if ( max_depth < 0 )
			{
				// If complexity was reduced already, pass.
				//
				if ( exp_new->complexity < exp->complexity )
					return true;

				// Try simplifying with maximum depth set as expression's
				// depth times two and pass if complexity was reduced.
				//
				try
				{
					lcache.begin_speculative();
					simplify_expression( exp_new, false, exp_new->depth * 2 );
					lcache.join_speculative();
					return exp_new->complexity < exp->complexity;
				}
				// If maximum depth was reached, revert any changes to the cache
				// and fail the join directive.
				//
				catch ( join_depth_exception& )
				{
					lcache.trash_speculative();
					return false;
				}
			}
			else
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
			}
		};

		// Enumerate each join descriptor:
		//
		for ( auto [dir_src, dir_dst] : get_join_descriptors( exp->op ) )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst, max_depth, filter ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_GRN>( "[Join] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s [By join directive]\n", *exp_new );
				log<CON_YLW>( "Complexity: %lf => %lf\n", exp->complexity, exp_new->complexity );
#endif
				// Recurse, set the hint and return the simplified instance.
				//
				simplify_expression( exp_new, pretty, max_depth - 1 );
				exp_new->simplify_hint = true;
				cache_entry = exp_new;
				if ( success_flag = !exp->is_identical( *exp_new ) )
					exp = exp_new;
				return success_flag;
			}
		}

		// If it is a boolean expression:
		//
		if ( exp->size() == 1 )
		{
			// Enumerate each join descriptor:
			//
			for ( auto [dir_src, dir_dst] : get_boolean_joiners( exp->op ) )
			{
				// If we can transform the expression by the directive set:
				//
				if ( auto exp_new = transform( exp, dir_src, dir_dst, max_depth, filter ) )
				{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
					log<CON_GRN>( "[Join] %s => %s\n", *dir_src, *dir_dst );
					log<CON_GRN>( "= %s [By join directive]\n", *exp_new );
					log<CON_YLW>( "Complexity: %lf => %lf\n", exp->complexity, exp_new->complexity );
#endif
					// Recurse, set the hint and return the simplified instance.
					//
					simplify_expression( exp_new, pretty, max_depth - 1 );
					exp_new->simplify_hint = true;
					cache_entry = exp_new;
					if ( success_flag = !exp->is_identical( *exp_new ) )
						exp = exp_new;
					return success_flag;
				}
			}
		}

		// Unpack the expression if requested:
		//
		if ( unpack )
		{
			// Enumerate each unpack descriptor:
			//
			for ( auto [dir_src, dir_dst] : get_unpack_descriptors( exp->op ) )
			{
				// If we can transform the expression by the directive set:
				//
				if ( auto exp_new = transform( exp, dir_src, dir_dst, max_depth,
					 [ & ] ( auto& exp_new ) { simplify_expression( exp_new, true, max_depth - 1 ); return exp_new->complexity < exp->complexity; } ) )
				{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
					log<CON_YLW>( "[Unpack] %s => %s\n", *dir_src, *dir_dst );
					log<CON_GRN>( "= %s [By unpack directive]\n", *exp_new );
#endif

					// Set the hint and return the simplified instance.
					//
					exp_new->simplify_hint = true;
					cache_entry = exp_new;
					if ( success_flag = !exp->is_identical( *exp_new ) )
						exp = exp_new;
					return success_flag;
				}
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