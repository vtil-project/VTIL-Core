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
#include <type_traits>
#include <vector>
#include <map>
#include "view.hpp"
#include "query_descriptor.hpp"
#include "../io/asserts.hpp"
#include "../util/variant.hpp"

namespace vtil::query
{
	// Thread local pointer to the current local mapping of stack variables.
	//
	namespace impl
	{
		using local_state_t = std::map<const void*, variant>;
		static thread_local local_state_t* local_state;
	};

	// Gets the recursive-local copy of the given variable on stack.
	//
	template<typename T>
	static T& rlocal( const T& alias )
	{
		fassert( impl::local_state );
		return impl::local_state->find( ( void* ) &alias )->second.get<T>();
	}
	template<typename P0, typename... PN>
	static std::tuple<P0&, PN&...> rlocal( const P0& p0, const PN&... pn )
	{
		return { rlocal<P0>( p0 ), rlocal<PN>( pn )... };
	}

	// Recursive results are used to collect results
	// in a way that clearly indicates the path taken
	// to get the result, and the source container.
	//
	template<typename result_type, typename container_type>
	struct recursive_result
	{
		// Whether we've visited this container before or not.
		//
		bool is_looping = false;
		
		// The container that the result belong to.
		//
		const container_type* source = nullptr;

		// Result of the collection.
		//
		result_type result;

		// Results of deeper recursions.
		//
		std::vector<recursive_result> paths;

		// Merges the results of all or extended basic-blocks.
		//
		template<typename>
		struct is_std_vector : std::false_type {};
		template<typename T, typename A>
		struct is_std_vector<std::vector<T, A>> : std::true_type {};
		recursive_result& flatten( bool force = false )
		{
			// Apply to each path recursively.
			//
			for ( auto& path : paths )
				path = path.flatten();

			// If single possible path or force mode:
			//
			if ( paths.size() == 1 || force )
			{
				std::vector paths_p = paths;
				paths.clear();

				for ( auto& r : paths_p )
				{
					// Merge basic result.
					//
					is_looping |= r.is_looping;
					if( !r.paths.empty() )
						paths.insert( paths.end(), r.paths.begin(), r.paths.end() );

					// Either combine vectors or use the addition operator.
					//
					if constexpr ( is_std_vector<result_type>::value )
						result.insert( result.end(), r.result.begin(), r.result.end() );
					else
						result += r.result;
				}
			}

			// Return as is.
			//
			return *this;
		}
	};

	template<typename view_type>
	struct recursive_view
	{
		// Base view and its typedefs.
		//
		using iterator_type = typename view_type::iterator_type;
		using projected_type = typename view_type::projected_type;
		using container_type = typename iterator_type::container_type;
		view_type view;

		// Container filters determine whether we should
		// recurse into the passed container or not.
		//
		using fn_container_filter = std::function<bool( const container_type* src, const container_type * dst, bool first_time )>;
		fn_container_filter filter = {};

		// Special iterator saved by the root to mark the 
		// beginning of it's iteration so loops can properly
		// lead to it.
		//
		iterator_type it0 = {};
		bool it0_oob = false;

		// List of containers that we've recursively visited.
		// The second argument of the container filter, first_time,
		// is determined by whether the container we're trying to
		// visit is in this list or not.
		//
		std::set<const void*> visited = {};

		// Maps the each local variable on caller stack to the recursive copies.
		//
		impl::local_state_t local_variables;

		// Binds the local variable to each possible recursive path,
		// should be called prior to the beginning of the iteration.
		//
		template<typename... PN>
		recursive_view& bind( const PN&... pn )
		{
			static constexpr auto ignore = [ ] ( ... ) {};
			ignore( ( local_variables[ &pn ] = pn )... );
			return *this;
		}

		// Constructs a recursive view from the view structure passed.
		//
		// - If partial visits are allowed, in case of an infinite loop,
		//   still iterates up to the starting point of view, first_time will
		//   be set to true in this case when we reach the root container.
		//
		// - Filter is a function that takes the pointer to the next container
		//   and whether it's being visit for the first time or not and returns
		//   whether we should visit it or not.
		//
		//
		recursive_view() = default;
		recursive_view( const view_type& view, bool partial_visits, fn_container_filter filter ) : view( view ), filter( filter )
		{
			// If partial visits are allowed:
			//
			if ( partial_visits )
			{
				// Set it0 as the next iterator, if invalid (meaning we'll skip to next
				// container right away) set the container property.
				//
				it0 = view.query.next();
				if ( !it0.is_valid() )
				{
					it0.container = view.query.iterator.container;
					it0_oob = true;
				}
			}
			else
			{
				// Assing an invalid iterator to it0 and mark current
				// iterator's container visited.
				//
				it0 = {};
				visited.insert( view.query.iterator.container );
			}
		}

		// Simply clones the current state.
		//
		recursive_view clone()
		{
			return *this;
		}

		// Simple wrappers around the real view.
		// - If body only contains unreachable(), call is not valid for recursive view.
		// - Collection must not have started yet, otherwise calls are invalid.
		//
		void prev() { unreachable(); }
		void next() { unreachable(); }
		void skip( int n = 1 ) { unreachable(); }
		void last() { unreachable(); }
		
		auto& reverse() { view.reverse(); return *this; }
		template<typename T> auto& run( T next ) { view.run( next ); return *this; }
		template<typename T> auto& with( T next ) { view.with( next ); return *this; }
		template<typename T> auto& where( T next ) { view.where( next ); return *this; }
		template<typename T> auto& until( T next ) { view.until( next ); return *this; }
		template<typename T> auto& whilst( T next ) { view.whilst( next ); return *this; }
		
		template<typename projector_type>
		auto project( projector_type next ) { return recursive_view<decltype( view.project( next ) )>{ view.project( next ), it0.container != nullptr, filter }; }
		template<typename projector_type>
		auto reproject( projector_type next ) { return recursive_view<decltype( view.reproject( next ) )>{ view.reproject( next ), it0.container != nullptr, filter }; }
		auto unproject() { return recursive_view<decltype( view.unproject() )>{ view.unproject(), it0.container != nullptr, filter }; }

		// [Collection method]
		// Invokes the enumerator for each entry, if enumerator returns void/bool
		// saves the number of (?=true) entries, otherwise collects the return value
		// in std::vector<> and saves that in the recursive_result structure.
		// Continues appending paths and results in that structure until
		// stream is finished.
		//
		template<typename enumerator_type,
			typename return_type = decltype( std::declval<enumerator_type>()( std::declval<projected_type>() ) ),
			typename result_type = std::conditional_t<std::is_same_v<return_type, void> || std::is_same_v<return_type, bool>, size_t, std::vector<return_type>>
		>
		recursive_result<result_type, container_type> for_each( const enumerator_type& enumerator )
		{
			// Set local state.
			//
			auto* prev_state = impl::local_state;
			impl::local_state = &local_variables;
			
			// Begin the iteration loop.
			//
			recursive_result<result_type, container_type> output = { false, view.query.iterator.container, {}, {} };
			while ( true )
			{
				int r = view.query.forward();

				// If a breaking condition was satisfied, end the loop.
				//
				if ( r == -1 )
				{
					break;
				}
				// If entry passed the filters, append the result and continue.
				//
				else if ( r == 1 )
				{
					if constexpr ( std::is_same_v<return_type, void> )
						output.result++, enumerator( view.prev() );
					else if constexpr ( std::is_same_v<return_type, bool> )
						output.result += enumerator( view.prev() );
					else
						output.result.push_back( enumerator( view.prev() ) );
				}
				// If we've reached the end of the stream, try recursing.
				//
				else
				{
					// For each plausible path:
					//
					std::vector desc_list = view.query.recurse();
					for ( auto& desc : desc_list )
					{
						auto visited_copy = visited;

						// If we did not already visit it:
						//
						bool first_visit = visited_copy.find( desc.iterator.container ) == visited_copy.end();
						if ( filter( view.query.iterator.container, desc.iterator.container, first_visit ) )
						{
							// Mark the container visited.
							//
							visited_copy.insert( desc.iterator.container );

							// Create another recursive view with the new query.
							//
							recursive_view view_new = clone();
							view_new.view.query = desc;
							view_new.visited = visited_copy;

							// If iterator belongs to the same container as the root:
							//
							bool partial_loop = desc.iterator.container == it0.container;
							if ( partial_loop )
							{
								// Append an additional rule to the iteration.
								//
								if( !it0_oob )
									view_new.view = view_new.view.until( it0 );
							}

							// Invoke the same enumerator and append as a path.
							//
							recursive_result<result_type, container_type> result = view_new.for_each<enumerator_type, return_type, result_type>( enumerator );
							result.is_looping = partial_loop;
							output.paths.push_back( result );
						}
						// Otherwise:
						//
						else
						{
							// Append an empty path marked as a loop.
							//
							output.paths.push_back( { true, view.query.iterator.container, {}, {} } );
						}
					}

					// Break out.
					//
					break;
				}
			}

			// Restore local state.
			//
			impl::local_state = prev_state;

			// Return the final result.
			//
			return output;
		}

		// [Collection method]
		// Collects each entry in std::vector<> and saves that in the 
		// recursive_result structure. Continues appending paths and 
		// results in that structure until stream is finished.
		//
		auto collect()
		{
			return for_each( [ ] ( projected_type r ) { return r; } );
		}

		// [Collection method]
		// Evaluates the iteration logic and returns the number of hits
		// in terms of recursive_result.
		//
		auto evaluate()
		{
			return for_each( [ ] ( projected_type r ) {} );
		}

		// [Collection method]
		// Collects first entry in std::vector<>, saves that in the 
		// recursive_result structure and stops if applicable. 
		// Otherwise continues appending paths in that structure 
		// until a valid entry is hit.
		//
		auto first()
		{
			auto prev = view.query.controller;
			view.query.controller = [ prev ] ( auto& self, iterator_type i ) -> int
			{
				// If current iterator reports end or filtered-out,
				// return as is.
				//
				int res = prev( self, i );
				if ( res <= 0 )
					return res;

				// Else, stop the query and return it to be processed.
				//
				self.stop();
				return 1;
			};
			return collect();
		}
	};

	// Converts the view to a recursive view. Since recursive view only contains collection
	// methods, all filtering/projection/iteration-logic should be processed at the base view.
	//
	template<typename view_type>
	static auto recurse( view_type view, typename recursive_view<view_type>::fn_container_filter filter = {}, bool partial_visits = true, bool safe = true )
	{
		return recursive_view<view_type>( view, partial_visits, [ filter, safe ] ( auto* src, auto* dst, bool first_time )
		{
			return ( !safe || first_time ) && ( !filter || filter( src, dst, true ) );
		} );
	}

	// Creates a reference-view query for the given query base.
	//
	template<typename iterator_type,
			 typename view_type = view<typename query_desc<iterator_type>::reference_type, query_desc<iterator_type>>
	>
	static auto create_recursive( query_desc<iterator_type> q, typename recursive_view<view_type>::fn_container_filter filter = {}, bool partial_visits = true, bool safe = true )
	{
		return recurse<view_type>
		(
			view_type( q ),
			filter,
			partial_visits,
			safe
		);
	}

	// Creates a reference-view query for the given range iterator.
	//
	template<typename iterator_type,
		typename view_type = view<typename query_desc<iterator_type>::reference_type, query_desc<iterator_type>>
	>
	static auto create_recursive( iterator_type r, int8_t dir = 0, typename recursive_view<view_type>::fn_container_filter filter = {}, bool partial_visits = true, bool safe = true )
	{
		return create_recursive( query_desc{ r, dir }, filter, partial_visits, safe );
	}
};