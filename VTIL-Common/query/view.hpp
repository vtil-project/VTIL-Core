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
#include <vector>
#include <optional>
#include <functional>
#include <type_traits>
#include "query_descriptor.hpp"

// To improve the readability of queries, each directive can be
// notated using the following guide using single-line comments.
//   => notates the beginning of a query.
//   >> notates skipping of a class / general directives on iteration [forwards]
//   << notates skipping of a class / general directives on iteration [backwards]
//   |  notates selection of a class
//   @  notates execution of a helper
//   := notates projection
//   <= notates collection (when return value is important)
//
namespace vtil::query
{
	// Query views provide the user with an interface interact
	// with any query in a simple fashion using a projected type
	// of their own choice.
	//
	template<typename _projected_type, typename _query_desc>
	struct view
	{
		using projected_type = _projected_type;
		using query_desc = _query_desc;
		using view_type = view<projected_type, query_desc>;

		// Base query and its typedefs.
		//
		query_desc query;
		using fn_controller = typename query_desc::fn_controller;
		using iterator_type = typename query_desc::iterator_type;
		using reference_type = typename query_desc::reference_type;

		// Projectors convert the iterator into a user-defined format
		// the invoker will be using.
		//
		using fn_projector = std::function<projected_type( query_desc&, iterator_type )>;
		fn_projector project_value;

		// Generic callback wrapper used so that expressions accepting the
		// projected type as an argument and expressions accepting the base
		// iterator type as an argument can be passed via the same function.
		//
		template<typename callback_type>
		struct callback_wrapper
		{
			// Storage of the callback in it's original type.
			//
			callback_type callback_stored;
			callback_wrapper( callback_type cb ) : callback_stored( cb ) {}

			// This definition will be used for callbacks that can accept the 
			// projected value over the iterator type where possible as it's the
			// prefered type.
			//
			template<typename fn_projector_i, typename = decltype( std::declval<callback_type>()( std::declval<projected_type>() ) )>
			auto invoke( iterator_type it, query_desc& desc, fn_projector_i project, bool ) const
			{
				return callback_stored( project( desc, it ) );
			}

			// This definition will be used for callbacks that can only work with the
			// iterator type and not the projected type. This is not the prefered method 
			// and that's an important distinction to make as in the situation of projected type
			// being std::next(it) for instance, this method being prefered would make it so that
			// the projector is ignored. That is not the case thanks to this method being the second
			// option.
			//
			template<typename fn_projector_i>
			auto invoke( iterator_type it, query_desc& desc, fn_projector_i project, ... ) const
			{
				return callback_stored( it );
			}

			// Calls into invoke with a boolean and picks whichever possible.
			//
			template<typename fn_projector_i>
			auto operator()( iterator_type it, query_desc& desc, fn_projector_i project ) const
			{
				return invoke( it, desc, project, true );
			}
		};

		// Constructor takes the query descriptor and a projector.
		//
		view( query_desc desc, fn_projector projector = {} ) : project_value( projector ), query( desc )
		{
			if ( !project_value )
			{
				if constexpr ( std::is_same_v<projected_type, reference_type> )
					project_value = [ ] ( auto&, iterator_type i ) -> projected_type { return *i; };
				else if constexpr ( std::is_same_v<iterator_type, projected_type> )
					project_value = [ ] ( auto&, iterator_type i ) -> projected_type { return i; };
				else
					unreachable();
			}
		}

		// Simply clones the current state of the view.
		//
		view clone()
		{
			return *this;
		}

		// These provide a simple wrapper around the query descrtiptor's
		// ::prev() and ::next() returning the projected value instead.
		//
		projected_type prev() { return project_value( query, query.prev() ); }
		projected_type next() { return project_value( query, query.next() ); }

		// Reverses the query descriptor's direction.
		//
		view_type& reverse()
		{
			query.reverse();
			return *this;
		}

		// Skips the [n] valid entries.
		//
		view_type& skip( int n = 1 )
		{
			query.forward( n );
			return *this;
		}

		// Returns the current controller.
		// This function can be used to implement query extensions
		// where one just passes the summarized controller of a dummy view
		// as an argument to a routine that creates the view after which the 
		// routine invokes ::control( arg ) on the real view.
		//
		fn_controller to_controller()
		{
			return query.controller;
		}

		// [Projection method]
		// Projects the current result type as specified by the projector and 
		// returns a new query view of that type.
		//
		template<typename projector_type, typename projected_type_n = decltype( std::declval<projector_type>()( std::declval<projected_type>() ) )>
		view<projected_type_n, query_desc> project( projector_type next )
		{
			// Save previous projector and create the new view
			//
			fn_projector prev = project_value;
			return view<projected_type_n, query_desc>
			{
				query,
				[ prev, next ] ( query_desc& self, iterator_type i ) -> projected_type_n
				{
					return next( prev( self, i ) );
				}
			};
		}

		// [Projection method]
		// Reverts the projected type to the iterator of the entry.
		//
		view<iterator_type, query_desc> unproject()
		{
			return view<iterator_type, query_desc>{ query };
		}

		// [Projection method]
		// Projects the iterator type as specified by the projector and 
		// returns a new query view of that type. (Equivalent to the 
		// combination of unproject + project)
		//
		template<typename projector_type, typename projected_type_n = decltype( std::declval<projector_type>()( std::declval<iterator_type>() ) )>
		view<projected_type_n, query_desc> reproject( projector_type next )
		{
			// Save previous projector and create the new view
			//
			return view<projected_type_n, query_desc>
			{
				query,
				[ next ] ( query_desc& self, iterator_type i ) -> projected_type_n
				{
					return next( i );
				}
			};
		}

		// [Combination method]
		// For each entry, invokes the controller and returns the integer
		// it returns as is. For more details on what this value 
		// represents, read the note for query_base::fn_controller and
		// ::to_controller()
		//
		view_type& control( fn_controller controller )
		{
			// Override iteration logic.
			//
			fn_controller prev = query.controller;
			query.controller = [ prev, controller ] ( query_desc& self, iterator_type i ) -> int
			{
				// If current iterator reports end or filtered-out,
				// return as is.
				//
				int res = prev( self, i );
				if ( res <= 0 )
					return res;
				// Else, run our additional layer of logic.
				//
				return controller( self, i );
			};
			return *this;
		}

		// [Filtering method]
		// For each entry, invokes the filter and if it returns false, 
		// skips it and continues from the next one.
		//
		template<typename callback_type>
		view_type& where( callback_type cb )
		{
			// Allow callbacks taking non-projected type if they take
			// the base iterator type.
			//
			fn_projector project = project_value;
			callback_wrapper<callback_type> callback = { cb };

			// Override iteration logic.
			//
			fn_controller prev = query.controller;
			query.controller = [ prev, project, callback ] ( query_desc& self, iterator_type i ) -> int
			{
				// If current iterator reports end or filtered-out,
				// return as is.
				//
				int res = prev( self, i );
				if ( res <= 0 )
					return res;
				// Else, run logic for our additional layer of filtering.
				//
				return callback( i, self, project ) ? 1 : 0;
			};
			return *this;
		}

		// [Filtering method]
		// For each entry, invokes the filter and if it returns true, 
		/// breaks out of the loop. If user provides an iterator instead
		// of a callback function, it breaks out of iteration when it
		// reaches that iterator instead.
		//
		template<typename argument_type>
		view_type& until( argument_type arg )
		{
			if constexpr ( !std::is_same_v<std::remove_cvref_t<argument_type>, iterator_type> )
			{
				// Allow callbacks taking non-projected type if they take
				// the base iterator type.
				//
				fn_projector project = project_value;
				callback_wrapper<argument_type> callback = { arg };

				// Override iteration logic.
				//
				fn_controller prev = query.controller;
				query.controller = [ prev, project, callback ] ( query_desc& self, iterator_type i ) -> int
				{
					// If current iterator reports end or filtered-out,
					// return as is.
					//
					int res = prev( self, i );
					if ( res <= 0 )
						return res;
					// Else, run logic for our additional layer of filtering.
					//
					return callback( i, self, project ) ? -1 : 1;
				};
				return *this;
			}
			else
			{
				// Override iteration logic.
				//
				fn_controller prev = query.controller;
				iterator_type stop_at = arg;
				query.controller = [ prev, stop_at ] ( query_desc& self, iterator_type i ) -> int
				{
					// Break if we reached the target iterator.
					//
					return i == stop_at ? -1 : prev( self, i );
				};
				return *this;
			}
		}

		// [Filtering method]
		// For each entry, invokes the filter and if it returns false, 
		/// breaks out of the loop.
		//
		template<typename callback_type>
		view_type& whilst( callback_type cb )
		{
			// Allow callbacks taking non-projected type if they take
			// the base iterator type.
			//
			fn_projector project = project_value;
			callback_wrapper<callback_type> callback = { cb };

			// Override iteration logic.
			//
			fn_controller prev = query.controller;
			query.controller = [ prev, project, callback ] ( query_desc& self, iterator_type i ) -> int
			{
				// If current iterator reports end or filtered-out,
				// return as is.
				//
				int res = prev( self, i );
				if ( res <= 0 )
					return res;
				// Else, run logic for our additional layer of filtering.
				//
				return callback( i, self, project ) ? 1 : -1;
			};
			return *this;
		}

		// [Filtering method]
		// For each entry valid in the current(!) conditions, invokes 
		// the given enumerator function.
		//
		template<typename callback_type>
		view_type& run( callback_type cb )
		{
			// Allow callbacks taking non-projected type if they take
			// the base iterator type.
			//
			fn_projector project = project_value;
			callback_wrapper<callback_type> callback = { cb };

			// Override iteration logic.
			//
			fn_controller prev = query.controller;
			query.controller = [ prev, project, callback ] ( query_desc& self, iterator_type i ) -> int
			{
				// If current iterator reports end or filtered-out,
				// return as is.
				//
				int res = prev( self, i );
				if ( res <= 0 )
					return res;
				// Else, invoke the enumerator and continue.
				//
				callback( i, self, project );
				return 1;
			};
			return *this;
		}

		// [Collection method]
		// Invokes the enumerator for each entry, if enumerator returns void/bool
		// returns the number of (?=true) entries, otherwise collects the return value
		// in std::vector<> and returns that.
		//
		template<typename enumerator_type>
		auto for_each( const enumerator_type& enumerator )
		{
			using T = decltype( enumerator( std::declval<projected_type>() ) );

			if constexpr ( std::is_same_v<T, void> )
			{
				size_t count = 0;
				while ( query.forward() == 1 )
					count++, enumerator( prev() );
				return count;
			}
			else if constexpr ( std::is_same_v<T, bool> )
			{
				size_t count = 0;
				while ( query.forward() == 1 )
					count += enumerator( prev() );
				return count;
			}
			else
			{
				std::vector<std::conditional_t<std::is_same_v<T, void>, int, T>> result;
				while ( query.forward() == 1 )
					result.push_back( enumerator( prev() ) );
				return result;
			}
		}

		// [Collection method]
		// Collects all entries in a vector and returns it as is.
		//
		std::vector<projected_type> collect()
		{
			return for_each( [ ] ( projected_type r ) { return r; } );
		}

		// [Collection method]
		// Evaluates the iteration logic and returns the number of hits.
		//
		auto evaluate()
		{
			return for_each( [ ] ( projected_type r ) {} );
		}

		// [Collection method]
		// Returns the first valid entry in the stream, nullopt if there were none.
		//
		std::optional<projected_type> first()
		{
			if ( query.forward() == 1 )
				return prev();
			return std::nullopt;
		}

		// [Collection method]
		// Returns the last valid entry in the stream, nullopt if there were none.
		//
		std::optional<projected_type> last()
		{
			std::optional<projected_type> res;
			while ( query.forward() == 1 )
				res = prev();
			return res;
		}
	};

	// Creates a reference-view query for the given query base.
	//
	template<typename iterator_type>
	static auto create( query_desc<iterator_type> q )
	{ 
		return view<typename query_desc<iterator_type>::reference_type, query_desc<iterator_type>>{ q };
	}

	// Creates a reference-view query for the given range iterator.
	//
	template<typename iterator_type>
	static auto create( iterator_type r, int8_t dir = 0 )
	{ 
		return create( query_desc{ r, dir } ); 
	}
	
	// Creates a dummy view that can be used to extract the summarized control logic.
	//
	template<typename iterator_type>
	static auto dummy() 
	{ 
		return create( query_desc<iterator_type>{} ); 
	}
};