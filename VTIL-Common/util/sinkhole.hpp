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
#include <map>
#include <functional>
#include <optional>
#include "../math/bitwise.hpp"
#include "../math/operable.hpp"
#include "../io/asserts.hpp"
#include "optional_reference.hpp"

namespace vtil
{
	namespace impl
	{
		template<typename T>
		struct mod_noop
		{
			T operator()( T&& p ) { return p; }
			const T& operator()( const T& p ) { return p; }
		};

		template<typename T>
		struct offset_by
		{
			T operator()( const T& a, int64_t d ) { return a + d; }
		};

		template<typename T>
		struct def_substract
		{
			std::optional<int64_t> operator()( const T& a, const T& b ) { return a - b; }
		};
	};

	// Value unit must implement:
	// - bitcnt_t T::size()
	// - void T::resize(bitcnt_t)
	// - operators | & << >>
	//
	template<typename pointer_unit, typename value_unit, 
		     typename weaken_pointer = impl::mod_noop<pointer_unit>, 
		     typename strong_predicate = std::less<pointer_unit>,
		     typename offset_fn = impl::offset_by<pointer_unit>,
	         typename distance_fn = impl::def_substract<pointer_unit>>
	struct sinkhole
	{
		// Common typedefs.
		//
		using cache_type =               std::map<pointer_unit, value_unit, strong_predicate>;
		using iterator =                 typename cache_type::iterator;
		using const_iterator =           typename cache_type::const_iterator;
		using default_constructor_type = std::function<value_unit( const pointer_unit& ptr, bitcnt_t size )>;

		// The constructor for default symbolic value of pointer dereferation. 
		// If none set, access to an unknown memory location will throw an exception.
		// 
		default_constructor_type default_constructor;

		// The memory cache.
		//
		cache_type value_map;

		// Default constructor, optionally takes a default constructor.
		//
		sinkhole( default_constructor_type default_constructor = {} )
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

			// Declare temporary result.
			//
			value_unit result = default_constructor( ptr, size );

			// Declare the list of iterators we will erase off the map upon
			// reorganizing and a hint to see if the key already exists.
			//
			std::optional<iterator> key_entry = {};
			stack_vector<iterator> merge_list;

			// Iterace each entry in the range:
			//
			auto it_min = value_map.lower_bound( offset_fn{}( weaken_pointer{}( ptr ), 64 / 8 ) );
			if ( it_min == value_map.end() ) return std::nullopt;
			auto it_max = value_map.upper_bound( offset_fn{}( ptr, size / 8 ) );
			if ( it_min == it_max ) return std::nullopt;
			for ( auto it = it_min; it != it_max; it++ )
			{
				// Calculate displacement, if unknown return unknown.
				// = [RL - WL]
				//
			retry:
				std::optional wl_b = distance_fn{}( it->first, ptr );
				if ( !wl_b )
				{
					if ( discard_value )
					{
						it = value_map.erase( it );
						if ( it == value_map.end() )
							break;
						goto retry;
					}
					return std::nullopt;
				}

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
						// Acquire upper bytes and use as is.
						//
						key_entry = acquire( it, rl - wl, rh - rl );
						result = ( *key_entry )->second;
						continue;
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
		value_unit read_v( const pointer_unit& ptr, bitcnt_t size )
		{
			return read( ptr, size ).value_or( default_constructor( ptr, size ) );
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
	};
};