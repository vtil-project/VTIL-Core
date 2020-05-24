#pragma once
#include <map>
#include <functional>
#include <optional>
#include "../math/bitwise.hpp"
#include "../math/operable.hpp"
#include "../io/asserts.hpp"
#include "optional_reference.hpp"

namespace vtil
{
	// Value unit must implement:
	// - bitcnt_t T::size()
	// - void T::resize(bitcnt_t)
	// - operators | & << >>
	//
	// Pointer unit must implement:
	// - operators ==, !=, >, -, +
	//   ^ are allowed to return optional values.
	//
	template<typename pointer_unit, typename value_unit>
	struct sinkhole
	{
		// Common typedefs.
		//
		using iterator =              typename std::map<pointer_unit, value_unit>::iterator;
		using const_iterator =        typename std::map<pointer_unit, value_unit>::const_iterator;
		using default_constructor_t = std::function<value_unit( const pointer_unit& ptr, bitcnt_t size )>;

		// The constructor for default symbolic value of pointer dereferation. 
		// If none set, access to an unknown memory location will throw an exception.
		// 
		default_constructor_t default_constructor;

		// The memory cache.
		//
		std::map<pointer_unit, value_unit> value_map;

		// Default constructor, optionally takes a default constructor.
		//
		sinkhole( default_constructor_t default_constructor = {} )
			: default_constructor( default_constructor ) {}

		// Default copy/move.
		//
		sinkhole( sinkhole&& ) = default;
		sinkhole( const sinkhole& ) = default;
		sinkhole& operator=( sinkhole&& ) = default;
		sinkhole& operator=( const sinkhole& ) = default;

		// Wrap around the map for iteration.
		//
		size_t size() const { return value_map.size(); }
		iterator begin() { return value_map.begin(); }
		iterator end() { return value_map.end(); }
		const_iterator begin() const { return value_map.begin(); }
		const_iterator end() const { return value_map.end(); }
		iterator erase( const_iterator x ) { return value_map.erase( std::move( x ) ); }

		// Given a cache entry's iterator, it strips N bits at the given offset
		// from it and creates another cache entry.
		//
		iterator acquire( iterator it, bitcnt_t offset, bitcnt_t size )
		{
			// Calculate high offsets.
			//
			bitcnt_t high_acq = offset + size;
			bitcnt_t high_own = it->second.size();

			// Split high.
			//
			if ( high_acq != high_own )
			{
				fassert( 0 < high_acq && high_acq < high_own );

				value_unit value_high = it->second >> high_acq;
				value_high.resize( high_own - high_acq );
				value_map.emplace_hint( it, it->first + ( high_acq / 8 ), std::move( value_high ) );
				it->second.resize( high_own = high_acq );
			}
			// Split middle.
			//
			if ( offset != 0 )
			{
				fassert( offset >= 0 );

				value_unit value_middle = it->second >> offset;
				value_middle.resize( size );
				it->second.resize( offset );
				it = value_map.emplace_hint( it, it->first + ( offset / 8 ), std::move( value_middle ) );
			}

			// Assert matching size and return.
			//
			fassert( it->second.size() == size );
			return it;
		}

		// Dereferences the pointer as reference.
		//
		template<bool discard_value = false>
		optional_reference<value_unit> dereference( const pointer_unit& ptr, bitcnt_t size )
		{
			// Validate the addressing.
			//
			fassert( size <= 64 && !( size & 7 ));

			// Find the iteration boundaries.
			//
			auto it_min = value_map.lower_bound( ptr - ( 64 / 8 ) );
			auto it_max = value_map.upper_bound( ptr + ( size / 8 ) );

			// Declare temporary result.
			//
			value_unit result = default_constructor( ptr, size );

			// Declare the list of iterators we will erase off the map upon
			// reorganizing and a hint to see if the key already exists.
			//
			std::optional<iterator> key_entry = {};
			stack_vector<iterator, 8> merge_list;

			// For each iterator within the range:
			//
			for ( auto it = it_min; it != it_max; it++ )
			{
				// Calculate displacement, if unknown return unknown.
				// = [RL - WL]
				//
				std::optional wl_b = it->first - ptr;
				if ( !wl_b )
					return std::nullopt;

				// Calculate all pointers.
				//
				const bitcnt_t rl = 0;
				const bitcnt_t rh = size;
				const bitcnt_t wl = wl_b.value() * 8;
				const bitcnt_t wh = wl + it->second.size();

				// If write is below or at our pointer:
				//    RL  |  RL
				// WL     |  WL
				//
				if ( wl <= rl )
				{
					// If write includes currently read boundary:
					// RH      |  RH
					//     WH  |  WH
					//
					if ( wh >= rh )
					{
						// Acquire upper bytes and return as is.
						//
						return acquire( it, rl - wl, rh - rl )->second;
					}

					// If write misses our range, skip.
					//       RL  RH
					// WL  WH	    
					//
					if ( wh <= rl )
						continue;

					// Read Low.
					//   RL  RH	| RL  RH
					// WL  WH	| WL  WH
					//
					it = acquire( it, rl - wl, wh - rl );
					if constexpr ( !discard_value )
					{
						result = result & ~math::fill( wh - rl );
						result = result | it->second;
					}
					
					// If displacement is zero, reference it as key hint, otherwise 
					// push to the merge list.
					// 
					if ( wl == 0 )
						key_entry = std::move( it );
					else
						merge_list.emplace_back( std::move( it ) );
				}
				// Else:
				//  RL      RH | RL      RH	| RL  RH    |  RL  RH
				//    WL  WH   |   WL  WH	|   WL  WH  |      WL  WH
				else
				{
					// Calculate the size of the overlapping region.
					//
					int64_t overlap_cnt = std::min( rh, wh ) - wl;
					
					// If write misses our range, skip.
					// RL  RH
					//     WL  WH	    
					//
					if ( overlap_cnt <= 0 )
						continue;

					// Read Mid/High.
					//  RL      RH | RL      RH	| RL  RH  
					//    WL  WH   |   WL  WH	|   WL  WH
					it = acquire( it, 0, overlap_cnt );
					if constexpr ( !discard_value )
					{
						value_unit mid_val = it->second;
						mid_val.resize( size );
						result = result & ~math::fill( overlap_cnt, wl );
						result = result | ( std::move( mid_val ) << wl );
					}
					merge_list.emplace_back( std::move( it ) );
				}
			}

			// Resize result.
			//
			result.resize( size );

			// Create the value entry if not re-used:
			//
			if ( !key_entry )
			{
				if ( merge_list.empty() )
					std::tie( key_entry, std::ignore ) = value_map.emplace( ptr, value_unit{} );
				else
					key_entry = value_map.emplace_hint( merge_list[ 0 ], ptr, value_unit{} );
			}

			// Write the value and erase all iterators in the merge list.
			//
			( *key_entry )->second = std::move( result );
			for ( auto it : merge_list )
				if( it != key_entry )
					value_map.erase( it );

			// Return the result as is.
			//
			return ( *key_entry )->second;
		}

		// Reads N bits from the given pointer.
		//
		optional_reference<value_unit> read( const pointer_unit& ptr, bitcnt_t size )
		{
			// Dereference and return as is.
			//
			return dereference<>( ptr, size );
		}

		// Writes the given value to the pointer.
		//
		optional_reference<value_unit> write( const pointer_unit& ptr, const value_unit& value )
		{
			// Dereference making sure value is discarded, if successful
			// overwrite it, otherwise create a new entry and reference it.
			//
			if ( optional_reference ref = dereference<true>( ptr, ( value.size() + 7 ) & ~7 ) )
				return *ref = value;
			else
				return value_map.emplace( ptr, value ).first->second;
		}

		// Simple way to access combining read and write.
		//
		optional_reference<value_unit> operator()( const pointer_unit& ptr, bitcnt_t size )
		{
			// Same logic as write but default case this time calls default constrcutor.
			//
			if ( optional_reference ref = dereference<true>( ptr, ( size + 7 ) & ~7 ) )
				return ref;
			return value_map.emplace( ptr, default_constructor( ptr, size ) ).first->second;
		}
	};
};