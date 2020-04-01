#pragma once
#include <vector>
#include <iterator>
#include <set>
#include "ranges.hpp"

namespace vtil::query
{
	// Query descriptor is a non-projected-type dependent structure
	// that describes the base state of any query object.
	//
	template<typename _iterator_type>
	struct query_desc
	{
		using iterator_type = _iterator_type;
		using reference_type = decltype( *std::declval<iterator_type>() );

		// Range iterator itself and the saved instance for at()
		//
		iterator_type iterator = {};

		// Direction of iteration:
		// => +1 for forward
		// => -1 for backwar
		//
		int8_t direction = 0;

		// Iteration function let's us define a generic iteration logic.
		//
		// Returns:
		// - 1 if there's a valid result
		// - 0 if reached end of the stream
		// - -1 if terminated due to until(...)
		//
		using fn_controller = std::function<int( query_desc&, iterator_type )>;
		fn_controller controller = [ ] ( auto&, auto ) { return 1; };

		// Queries can be simply constructed from an iterator and an
		// optional direction value, where it defaults to forward iteration
		// if not .end(), backwards otherwise.
		//
		query_desc() {};
		query_desc( _iterator_type it, int8_t dir = 0 ) : iterator( it )
		{
			if ( it.is_end() && !it.is_begin() )
				direction = dir != 0 ? dir : -1;
			else
				direction = dir != 0 ? dir : +1;
		}

		// Wraps ::recurse(...) of range iterators, returning query descriptors.
		//
		std::vector<query_desc> recurse() const
		{
			// Return an empty list if direction is invalid.
			//
			if ( direction == 0 ) return {};

			// Get the list of possible iterators we could continue from.
			//
			std::vector iterators = iterator.recurse( direction == +1 );

			// Convert into query descriptors.
			//
			std::vector<query_desc> query_descriptors;
			for ( iterator_type& it : iterators )
			{
				// Create a default descriptor with the iterator and the direction,
				// afterwards propagate the iteration logic.
				//
				query_desc qd = { it, direction };
				qd.controller = controller;
				query_descriptors.push_back( qd );
			}
			return query_descriptors;
		}

		// Invalidates current query.
		//
		void stop()
		{
			iterator = prev();
			direction = 0;
		}

		// Value that next() processed previously.
		//
		auto prev() const { return direction != +1 ? iterator : ( iterator.is_begin() ? iterator_type{} : std::prev( iterator ) ); }

		// Value that next() will process next.
		//
		auto next() const { return direction != -1 ? iterator : ( iterator.is_begin() ? iterator_type{} : std::prev( iterator ) ); }

		// Reverses the current query direction
		//
		void reverse()
		{
			// We have to fix the iterators since
			// .end() is valid for [-1] but not [+1]
			// and .begin() is valid for [+1] but not [-1].
			//
			if ( direction == -1 )
			{
				if ( !iterator.is_begin() ) iterator--;
				direction = +1;
			}
			else if ( direction == +1 )
			{
				if ( !iterator.is_end() ) iterator++;
				direction = -1;
			}
		}

		// Forwards the iterator in the specified direction [n] times.
		//
		int forward( int n = 1 )
		{
			// Until we exhaust the item counter: 
			//
			while ( n > 0 )
			{
				// If direction is backwards:
				//
				if ( direction == -1 )
				{
					// If we've reached .begin(), break.
					//
					if ( iterator.is_begin() )
						break;

					// Point the iterator at the current item.
					//
					iterator--;

					// If invalid, break.
					//
					if ( !iterator.is_valid() )
						break;
				}
				// If direction is forwards:
				//
				else if ( direction == +1 )
				{
					// If we've reached .end(), break.
					//
					if ( iterator.is_end() )
						break;
				}
				// If no direction specified, break.
				//
				else
				{
					break;
				}

				// Invoke the iteration logic.
				//
				int res = controller( *this, iterator );

				// If direction was forward, increment the iterator now.
				//
				if ( direction == +1 )
					iterator++;

				// If a breaking condition was satisfied, report so.
				//
				if ( res == -1 )
					return -1;

				// If filters were passed and we've exhausted the
				// item counter, report success.
				//
				if ( res == 1 && --n <= 0 )
					return 1;
			}

			// Report end-of-stream.
			//
			return 0;
		}
	};
};