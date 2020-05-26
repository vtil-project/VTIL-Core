#include "cached_tracer.hpp"

namespace vtil
{
	// Hooks default tracer and does a cache lookup before invokation.
	//
	symbolic::expression cached_tracer::trace( symbolic::variable lookup )
	{
		using namespace logger;

	#if VTIL_OPT_TRACE_VERBOSE
		// Log the beginning of the trace.
		//
		log<CON_BRG>( "CcTrace(%s)\n", lookup );
		scope_padding _p( 1 );
	#endif
		// Handle base case.
		//
		if ( lookup.at.is_begin() )
		{
			symbolic::expression result = lookup.to_expression();
	#if VTIL_OPT_TRACE_VERBOSE
			// Log result.
			//
			log<CON_BRG>( "= %s [Base case]\n", result );
	#endif
			return result;
		}

		// Try lookup the exact variable in the map in a fast manner.
		//
		auto it = cache.find( lookup );
		if ( it != cache.end() )
		{
			const symbolic::expression& result = *it->second;
	#if VTIL_OPT_TRACE_VERBOSE
			// Log result.
			//
			log<CON_BLU>( "= %s [Cached result]\n", result );
	#endif
			return result;
		}
		// Declare a predicate for the search of the variable in the cache.
		//
		std::function<bool( const cache_entry& )> predicate;

		// If memory variable:
		//
		if ( lookup.is_memory() )
		{
			predicate = [ & ] ( const cache_entry& pair )
			{
				// Key must be of memory type at the same position.
				//
				if ( !pair.first.is_memory() ) return false;
				if ( pair.first.at != lookup.at ) return false;

				// Must be the same pointer and have a larger or equal size.
				//
				auto& self = lookup.mem();
				auto& other = pair.first.mem();
				return self.decay().equals( other.decay() ) &&
					self.bit_count >= other.bit_count;
			};
		}
		// If register variable:
		//
		else
		{
			fassert( lookup.is_register() );
			predicate = [ & ] ( const cache_entry& pair )
			{
				// Key must be of memory type at the same position.
				//
				if ( !pair.first.is_register() ) return false;
				if ( pair.first.at != lookup.at ) return false;

				// Must be the same register and have a larger or equal size.
				//
				auto& self = lookup.reg();
				auto& other = pair.first.reg();
				return self.flags == other.flags &&
					self.local_id == other.local_id &&
					self.bit_offset == other.bit_offset &&
					self.bit_count >= other.bit_count;
			};
		}

		// Search the map, if we find a matching entry shrink and use as the result.
		//
		symbolic::expression result;
		it = std::find_if( cache.begin(), cache.end(), predicate );
		if ( it != cache.end() )
			result = symbolic::expression{ *it->second }.resize( lookup.bit_count() );
		else
			result = tracer::trace( lookup );

		// Insert a cache entry for the exact variable we're looking up and return.
		//
		cache.emplace( lookup, result );

	#if VTIL_OPT_TRACE_VERBOSE
		// Log result.
		//
		log<CON_BRG>( "= %s\n", result );
	#endif
		return result;
	}
};