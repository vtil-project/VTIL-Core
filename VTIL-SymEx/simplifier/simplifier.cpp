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

// [Configuration]
// Determine the depth limit after which we start self generated signature matching and
// the properties of the LRU cache.
//
#ifndef VTIL_SYMEX_SELFGEN_SIGMATCH_DEPTH_LIM
	#define	VTIL_SYMEX_SELFGEN_SIGMATCH_DEPTH_LIM   3
#endif
#ifndef VTIL_SYMEX_LRU_CACHE_SIZE
	#define VTIL_SYMEX_LRU_CACHE_SIZE               0x10000
#endif
#ifndef VTIL_SYMEX_LRU_PRUNE_COEFF
	#define VTIL_SYMEX_LRU_PRUNE_COEFF              0.35
#endif
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

	using dynamic_directive_table =       std::vector<dynamic_directive_table_entry>;
	using organized_directive_table =     std::array<dynamic_directive_table, ( size_t ) math::operator_id::max>;

	template<typename T>
	static organized_directive_table build_dynamic_table( const T& container )
	{
		organized_directive_table table;
		for ( auto [table, op] : zip( table, iindices ) )
			for( auto& directive : container )
				if ( directive.first.op == ( math::operator_id ) op )
					table.emplace_back( &directive.first, &directive.second );
		return table;
	};

	static auto& get_boolean_joiners( math::operator_id op )       { static const auto tbl = build_dynamic_table( directive::boolean_joiners );             return tbl[ ( size_t ) op ]; }
	static auto& get_pack_descriptors( math::operator_id op )      { static const auto tbl = build_dynamic_table( directive::pack_descriptors );            return tbl[ ( size_t ) op ]; }
	static auto& get_join_descriptors( math::operator_id op )      { static const auto tbl = build_dynamic_table( directive::join_descriptors );            return tbl[ ( size_t ) op ]; }
	static auto& get_unpack_descriptors( math::operator_id op )    { static const auto tbl = build_dynamic_table( directive::unpack_descriptors );          return tbl[ ( size_t ) op ]; }
	static auto& get_boolean_simplifiers( math::operator_id op )   { static const auto tbl = build_dynamic_table( directive::build_boolean_simplifiers() ); return tbl[ ( size_t ) op ]; }
	static auto& get_universal_simplifiers( math::operator_id op ) { static const auto tbl = build_dynamic_table( directive::universal_simplifiers );       return tbl[ ( size_t ) op ]; }

	// Thread local simplifier state.
	//
	struct simplifier_state
	{
		static constexpr size_t max_cache_entries = VTIL_SYMEX_LRU_CACHE_SIZE;
		static constexpr size_t cache_prune_count = ( size_t ) ( max_cache_entries * VTIL_SYMEX_LRU_PRUNE_COEFF );

		// Declare custom hash / equivalence checks hijacking the hash map iteration.
		//
		struct cache_value
		{
			// Type of the queue key.
			//
			using queue_key = typename detached_queue<cache_value>::key;

			// Entry itself:
			//
			expression::reference result = {};
			bool is_simplified = false;

			// Implementation details:
			//
			int32_t lock_count = 0;
			queue_key lru_key = {};
			queue_key spec_key = {};

			// Stores a type erased iterator since we don't know the map type yet, only
			// an issue with libstdc++ but oh well.
			// - Ref: https://github.com/vtil-project/VTIL-Core/issues/41
			//
			std::unordered_map<uint64_t, uint64_t>::const_iterator _iterator = {};
			
			template<typename map_type>
			auto& iterator()
			{
				using iterator_type = typename map_type::const_iterator;
				static_assert( sizeof( iterator_type ) == sizeof( _iterator ), "Iterator sizes mismatch." );
				return ( iterator_type& ) _iterator;
			}
			template<typename map_type>
			const auto& iterator() const { return make_mutable( this )->template iterator<map_type>(); }
		};


		struct signature_hasher
		{
			size_t operator()( const expression::reference& ref ) const noexcept { return ref->signature.hash(); }
		};

		struct cache_scanner
		{
			struct sigscan_result
			{
				const expression::reference& key;
				cache_value* match = nullptr;
				expression::uid_relation_table table;
				int64_t diff = 0;
			};
			inline static thread_local sigscan_result* sigscan = nullptr;

			bool operator()( const expression::reference& a, const expression::reference& b ) const noexcept 
			{ 
				// If there's a signature matching request:
				//
				if ( sigscan )
				{
					// Find out which argument is "this", if failed return false.
					//
					auto self = &a, other = &b;
					if ( a.pointer != sigscan->key.pointer )
						std::swap( self, other );

					// Skip if not improving the result.
					//
					int64_t sdiff = ( *self )->depth - ( *other )->depth;
					//if ( sdiff < 0 )
					if( sdiff != 0  )
						return false;
					if ( sigscan->match && sdiff > sigscan->diff )
						return false;

					// Redirect to is identical if they're the same depth:
					//
					if ( sdiff == 0 && a.is_identical( *b ) )
						return true;

					// If other's past depth limit:
					//
					if ( ( *other )->depth > VTIL_SYMEX_SELFGEN_SIGMATCH_DEPTH_LIM )
					{
						// If matching signature, save the match, steal full value from the reference to the key.
						//
						if ( auto vec = ( *other )->match_to( **self, /*false*/ true ) )
						{
							sigscan->table = std::move( *vec );
							using kv_pair = std::pair<const expression::reference, cache_value>;
							sigscan->match = &( ( kv_pair* ) other )->second;
							sigscan->diff = sdiff;
							sigscan = nullptr;
						}
					}
					return false;
				}
				// If not sigscanning, check if identical.
				//
				else
				{
					return a.is_identical( *b );
				}
			}
		};

		// Cache entry and map type.
		//
		using cache_map = std::unordered_map<expression::reference, cache_value, signature_hasher, cache_scanner>;

		// Whether we're executing speculatively or not.
		//
		bool is_speculative = false;

		// Queue for LRU age tracking and the speculativeness.
		//
		detached_queue<cache_value> lru_queue;
		detached_queue<cache_value> spec_queue;

		// Cache map.
		//
		cache_map map{ max_cache_entries };

		// Disallow copy.
		//
		simplifier_state() {}
		simplifier_state( simplifier_state&& ) = default;
		simplifier_state( const simplifier_state& ) = delete;
		simplifier_state& operator=( simplifier_state&& ) = default;
		simplifier_state& operator=( const simplifier_state& ) = delete;

		// Resets the local cache.
		//
		void reset()
		{
			lru_queue.reset();
			spec_queue.reset();
			is_speculative = false;
			map.clear();
			map.reserve( max_cache_entries );
		}

		// Begins speculative execution.
		//
		void begin_speculative()
		{
			is_speculative = true;
		}

		// Ends speculative execution and marks all speculative entries valid.
		//
		void join_speculative()
		{
			for ( auto it = spec_queue.head; it; )
			{
				auto next = it->next;
				spec_queue.erase( it );
				it = next;
			}
			is_speculative = false;
		}

		// Ends speculative execution and trashes all incomplete speculative entries.
		//
		void trash_speculative()
		{
			spec_queue.pop_front( &cache_value::spec_key );

			for ( auto it = spec_queue.head; it; )
			{
				auto next = it->next;
				cache_value* value = it->get( &cache_value::spec_key );
				fassert( value->lock_count <= 0 );

				if ( value->is_simplified )
					spec_queue.erase( it );
				else
					erase( value );
				it = next;
			}
			is_speculative = false;
		}

		// Erases a cache entry.
		//
		void erase( cache_value* value )
		{
			fassert( value->lock_count == 0 );
			lru_queue.erase( &value->lru_key );
			if( value->spec_key.is_valid() )
				spec_queue.erase( &value->spec_key );
			map.erase( std::move( value->template iterator<cache_map>() ) );
		}

		// Initializes a new entry in the map.
		//
		void init_entry( const cache_map::iterator& entry_it )
		{
			// Save the iterator.
			//
			entry_it->second.template iterator<cache_map>() = entry_it;

			// If simplifying speculatively, link to tail.
			//
			if ( is_speculative )
				spec_queue.emplace_back( &entry_it->second.spec_key );

			// If we reached max entries, prune:
			//
			if ( lru_queue.size() == ( max_cache_entries - 1 ) )
			{
				for ( auto it = lru_queue.head; it && ( lru_queue.size() + cache_prune_count ) > max_cache_entries; )
				{
					auto next = it->next;
					// Erase if not locked:
					//
					cache_value* value = it->get( &cache_value::lru_key );
					if ( value->lock_count <= 0 )
						erase( value );
					it = next;
				}
			}
		}

		// References to cache from the active scope.
		//
		struct scope_reference
		{
			using queue_key = typename detached_queue<scope_reference>::key;

			detached_queue<scope_reference>& queue;
			cache_value* value;
			queue_key key;
			
			scope_reference( detached_queue<scope_reference>& queue, cache_value* value )
				: queue( queue ), value( value ) { ++value->lock_count; queue.emplace_back( &key ); }
			~scope_reference() { queue.erase( &key ); fassert( --value->lock_count >= 0 ); }

			scope_reference( scope_reference&& o ) = delete;
			scope_reference( const scope_reference& o ) = delete;
			scope_reference& operator=( scope_reference&& o ) = delete;
			scope_reference& operator=( const scope_reference& o ) = delete;
		};
		detached_queue<scope_reference> scope;
		
		// Maximum allowed depth, once reached will reset to 0 to make all calls recursively fail.
		//
		uint64_t max_depth = ~0;

		// Looks up the cache for the expression, returns [<result>, <simplified?>, <exists?>, <entry>].
		//
		std::tuple<expression::reference&, bool&, bool, cache_value*> lookup( const expression::reference& exp )
		{
			// Signal signature matcher.
			//
			cache_scanner::sigscan_result sig_search = { exp };
			cache_scanner::sigscan = exp->depth > VTIL_SYMEX_SELFGEN_SIGMATCH_DEPTH_LIM ? &sig_search : nullptr;

			// Make sure we don't rehash and then emplace/find.
			//
			fassert( ( map.max_load_factor() * map.bucket_count() ) >= ( map.size() + 1 ) );
			auto [it, inserted] = map.emplace( exp, make_default<cache_value>() );
			cache_scanner::sigscan = nullptr;

			// Speculatively lock the entry.
			//
			it->second.lock_count++;

			// If we inserted a new entry:
			//
			if ( inserted )
			{
				// If there is a partial match:
				//
				if ( auto base = sig_search.match )
				{
					// Reset inserted flag.
					//
					inserted = false;

					// If simplified, transform according to the UID table.
					//
					if ( base->is_simplified )
					{
						it->second.result = make_const( base->result ).transform( [ &sig_search ] ( expression::delegate& exp )
						{
							if ( !exp->is_variable() )
								return;
							for ( auto& [a, b] : sig_search.table )
							{
								if ( exp->is_identical( *a ) )
								{
									exp = b.make_shared();
									break;
								}
							}
						}, true, false );
						it->second.result->simplify_hint = true;
						it->second.is_simplified = true;
					}
					// Otherwise, declare failure.
					//
					else
					{
						it->second.is_simplified = false;
					}

					// Erase or at least de-prioritize the previous entry.
					//
					if ( base->lock_count <= 0 )
					{
						erase( base );
					}
					else
					{
						lru_queue.erase( &base->lru_key );
						lru_queue.emplace_front( &base->lru_key );
					}
				}

				// Initialize it.
				//
				init_entry( it );
			}
			else
			{
				lru_queue.erase( &it->second.lru_key );
			}

			// Remove speculative lock.
			//
			it->second.lock_count--;

			// Insert into the tail of use list.
			//
			lru_queue.emplace_back( &it->second.lru_key );
			return { it->second.result, it->second.is_simplified, !inserted, &it->second };
		}
	};

	static task_local( simplifier_state ) local_state;
	void purge_simplifier_state() { if( local_state.init ) local_state->reset(); }

	simplifier_state_ptr swap_simplifier_state( simplifier_state_ptr p ) 
	{ 
		if ( p )
		{
			std::swap( *p, *local_state );
			return p;
		}
		else if( local_state.init )
		{
			return { new simplifier_state( local_state.steal() ), simplifier_state_deleter{} };
		}
		else
		{
			return nullptr;
		}
	}
	void simplifier_state_deleter::operator()( simplifier_state* p ) const noexcept { delete p; }
	simplifier_state_ptr simplifier_state_allocator::operator()() const noexcept    { return { new simplifier_state, simplifier_state_deleter{} }; }


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
				simplify_expression( exp, true, false );
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
			if ( auto exp_new = transform( exp, dir_src, dir_dst ) )
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
	static std::pair<bool, expression::weak_reference> match_boolean_expression( const expression::reference& exp )
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

				if ( !p2 ) return { true, p1 };
				if ( !p1 ) return { true, p2 };

				if ( p1->uid == p2->uid )
					return { true, p1 };
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
		expression::reference exp_new = uid_base.make_shared();
		if ( and_mask != ~0ull )  exp_new &= expression{ and_mask, exp->size() };
		if ( xor_mask )           exp_new ^= expression{ xor_mask, exp->size() };
		if ( or_mask )            exp_new |= expression{ or_mask,  exp->size() };

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
	static bool simplify_expression_i( expression::reference& exp, bool pretty, bool unpack )
	{
		auto& lstate = *local_state;
		using namespace logger;

		// If we've reached the maximum depth, recursively fail.
		//
		if ( lstate.scope.size() >= lstate.max_depth )
		{
			lstate.max_depth = 0;
			return false;
		}

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
			*+exp = expression{ exp->value.known_one(), exp->value.size() };
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
		auto [cache_entry, success_flag, found, entry] = lstate.lookup( exp );
		simplifier_state::scope_reference _g{ lstate.scope, entry };

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
			bool simplified = simplify_expression( exp_new, pretty, unpack );
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
			simplify_expression( exp, pretty );
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
		for ( auto& [dir_src, dir_dst] : get_universal_simplifiers( exp->op ) )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_GRN>( "[Simplify] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s [By simplify directive]\n", *exp_new );
#endif
				// Recurse, set the hint and return the simplified instance.
				//
				simplify_expression( exp_new, pretty );
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
			for ( auto& [dir_src, dir_dst] : get_boolean_simplifiers( exp->op ) )
			{
				// If we can transform the expression by the directive set:
				//
				if ( auto exp_new = transform( exp, dir_src, dir_dst ) )
				{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
					log<CON_GRN>( "[Simplify] %s => %s\n", *dir_src, *dir_dst );
					log<CON_GRN>( "= %s [By simplify directive]\n", *exp_new );
#endif
					// Recurse, set the hint and return the simplified instance.
					//
					simplify_expression( exp_new, pretty );
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
		auto filter = [ & ] ( auto& exp_new )
		{
			if ( !lstate.is_speculative )
			{
				// If complexity was reduced already, pass.
				//
				if ( exp_new->complexity < exp->complexity )
					return true;

				// Try simplifying with maximum depth set as expression's
				// depth times two and pass if complexity was reduced.
				//
				auto pscope = lstate.scope;
				lstate.max_depth = pscope.size() + exp_new->depth * 2;
				lstate.begin_speculative();
				simplify_expression( exp_new, false );

				// If maximum depth was reached, revert any changes to the cache
				// and fail the join directive.
				//
				if ( lstate.max_depth == 0 )
				{
					lstate.trash_speculative();
					lstate.scope = pscope;
					lstate.scope.tail->next = nullptr;
					lstate.max_depth = ~0;
					return false;
				}
				else
				{
					lstate.join_speculative();
					lstate.max_depth = ~0;
					return exp_new->complexity < exp->complexity;
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
				simplify_expression( exp_new, false );
				return exp_new->complexity < exp->complexity;
			}
		};

		// Enumerate each join descriptor:
		//
		for ( auto& [dir_src, dir_dst] : get_join_descriptors( exp->op ) )
		{
			// If we can transform the expression by the directive set:
			//
			if ( auto exp_new = transform( exp, dir_src, dir_dst, filter ) )
			{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
				log<CON_GRN>( "[Join] %s => %s\n", *dir_src, *dir_dst );
				log<CON_GRN>( "= %s [By join directive]\n", *exp_new );
				log<CON_YLW>( "Complexity: %lf => %lf\n", exp->complexity, exp_new->complexity );
#endif
				// Recurse, set the hint and return the simplified instance.
				//
				simplify_expression( exp_new, pretty );
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
			for ( auto& [dir_src, dir_dst] : get_boolean_joiners( exp->op ) )
			{
				// If we can transform the expression by the directive set:
				//
				if ( auto exp_new = transform( exp, dir_src, dir_dst, filter ) )
				{
#if VTIL_SYMEX_SIMPLIFY_VERBOSE
					log<CON_GRN>( "[Join] %s => %s\n", *dir_src, *dir_dst );
					log<CON_GRN>( "= %s [By join directive]\n", *exp_new );
					log<CON_YLW>( "Complexity: %lf => %lf\n", exp->complexity, exp_new->complexity );
#endif
					// Recurse, set the hint and return the simplified instance.
					//
					simplify_expression( exp_new, pretty );
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
			for ( auto& [dir_src, dir_dst] : get_unpack_descriptors( exp->op ) )
			{
				// If we can transform the expression by the directive set:
				//
				if ( auto exp_new = transform( exp, dir_src, dir_dst,
					 [ & ] ( auto& exp_new ) { simplify_expression( exp_new, true ); return exp_new->complexity < exp->complexity; } ) )
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

	// Simple routine wrapping real simplification to instrument it for any reason when needed.
	//
	bool simplify_expression( expression::reference& exp, bool pretty, bool unpack )
	{
		return simplify_expression_i( exp, pretty, unpack );
	}
};