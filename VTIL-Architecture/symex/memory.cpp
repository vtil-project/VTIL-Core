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
#include <vtil/math>
#include "memory.hpp"

namespace vtil::symbolic
{
	// Returns the mask of known/unknown bits of the given region, if alias failure occurs returns nullopt.
	//
	std::optional<uint64_t> memory::known_mask( const pointer& ptr, bitcnt_t size ) const
	{
		if ( auto value = unknown_mask( ptr, size ) )
			return math::fill( size ) & ~*value;
		else
			return std::nullopt;
	}
	std::optional<uint64_t> memory::unknown_mask( const pointer& ptr, bitcnt_t size ) const
	{
		uint64_t mask_pending = math::fill( size );

		// For each entry, iterating backwards:
		//
		for ( auto it = value_map.rbegin(); it != value_map.rend() && mask_pending; it++ )
		{
			// If pointer cannot overlap lookup, skip.
			//
			if ( !it->first.can_overlap( ptr ) )
				continue;

			// Calculate displacement, if unknown return unknown.
			//
			std::optional byte_distance = it->first - ptr;
			if ( !byte_distance )
				return std::nullopt;

			// Calculate relative mask, clear pending mask.
			//
			bitcnt_t bit_distance = math::narrow_cast<bitcnt_t>( *byte_distance * 8 );
			uint64_t relative_mask = math::fill( it->second.size(), bit_distance );
			mask_pending &= ~relative_mask;
		}
		return mask_pending;
	}

	// Reads N bits from the given pointer, returns null reference if alias failure occurs.
	// - Will output the mask of bits contained in the state into contains if it does not fail.
	//
	expression::reference memory::read( const pointer& ptr, bitcnt_t size, const il_const_iterator& reference_iterator, uint64_t* contains ) const
	{
		uint64_t tmp;
		if ( !contains ) contains = &tmp;

		uint64_t mask_pending = math::fill( size );
		stack_vector<std::pair<bitcnt_t, expression::reference>, 8> merge_list;

		// For each entry, iterating backwards:
		//
		for ( auto it = value_map.rbegin(); it != value_map.rend() && mask_pending; it++ )
		{
			// If pointer cannot overlap lookup, skip.
			//
			if ( !it->first.can_overlap( ptr ) )
				continue;

			// Calculate displacement, if unknown:
			//
			std::optional byte_distance = it->first - ptr;
			if ( !byte_distance )
			{
				// If not relaxed aliasing, indicate alias failure by returning null.
				//
				if ( !relaxed_aliasing )
					return nullptr;

				// Otherwise, return default value, cannot be determined.
				//
				merge_list.clear();
				break;
			}

			// Calculate relative mask, skip if not overlapping.
			//
			bitcnt_t bit_distance = math::narrow_cast<bitcnt_t>( *byte_distance * 8 );
			uint64_t relative_mask = math::fill( it->second.size(), bit_distance );
			if ( !( relative_mask & mask_pending ) )
				continue;

			// Add into merge list, clear the mask.
			//
			merge_list.emplace_back( bit_distance, it->second );
			mask_pending &= ~relative_mask;
		}

		// If no overlapping keys found, return default.
		//
		*contains = math::fill( size ) & ~mask_pending;
		if ( !*contains )
			return MEMORY( reference_iterator )( ptr, size );

		// Declare common bit selector.
		//
		constexpr auto select = [ ] ( symbolic::expression::reference& value, bitcnt_t size, bitcnt_t offset )
		{
			if ( offset < 0 )      value >>= -offset, value.resize( size );
			else if ( offset > 0 ) value.resize( size ) <<= offset;
			else                   value.resize( size );
		};

		// If single overlapping key with no pending bits, return as is.
		//
		if ( !mask_pending && merge_list.size() == 1 )
		{
			auto&& [dst, value] = std::move( merge_list[ 0 ] );
			select( value, size, dst );
			return value;
		}

		// Merge all in a single expression and return.
		//
		expression::reference result = mask_pending
			? MEMORY( reference_iterator )( ptr, size )
			: expression{ 0, size };

		for ( auto& [dst, value] : merge_list )
		{
			select( value, size, dst );
			result |= std::move( value );
		}
		return result;
	}

	// Writes the given value to the pointer, returns null reference if alias failure occurs.
	//
	optional_reference<expression::reference> memory::write( const pointer& ptr, deferred_value<expression::reference> value, bitcnt_t size )
	{
		uint64_t mask_pending = math::fill( size );
		stack_vector<std::pair<bitcnt_t, store_type::iterator>, 8> acquisition_list;

		// For each entry, iterating backwards:
		//
		for ( auto it = value_map.rbegin(); it != value_map.rend() && mask_pending; it++ )
		{
			// If pointer cannot overlap lookup, skip.
			//
			if ( !it->first.can_overlap( ptr ) )
				continue;

			// Calculate displacement, if unknown:
			//
			std::optional byte_distance = it->first - ptr;
			if ( !byte_distance )
			{
				// If not relaxed aliasing, indicate alias failure by returning null.
				//
				if ( !relaxed_aliasing )
					return std::nullopt;

				// Otherwise, insert at the end, overlaps can't be determined.
				//
				acquisition_list.clear();
				break;
			}

			// Calculate relative mask, skip if not overlapping.
			//
			bitcnt_t bit_distance = math::narrow_cast<bitcnt_t>( *byte_distance * 8 );
			uint64_t relative_mask = math::fill( it->second.size(), bit_distance );
			if ( !( relative_mask & mask_pending ) )
				continue;

			// Add into acquisition list, clear the mask.
			//
			acquisition_list.emplace_back( bit_distance, std::prev( it.base() ) );
			mask_pending &= ~relative_mask;
		}

		// For each iterator we should acquire bits from:
		//
		for ( auto& [dst, it] : acquisition_list )
		{
			// If low bits start at or above our pointer:
			// | v v v v         |  v v v v		|
			// |     a b c d ... |  a b c d ... |
			//
			if ( dst >= 0 )
			{
				bitcnt_t strip_low_cnt = size - dst;
				bitcnt_t new_size = it->second->size() - strip_low_cnt;

				// If value is completely overwritten, erase and continue.
				//
				if ( new_size <= 0 )
				{
					value_map.erase( it );
					continue;
				}

				// Shift and resize the entry.
				//
				it->first = std::move( it->first ) + ( strip_low_cnt / 8 );
				it->second >>= strip_low_cnt;
				it->second.resize( new_size );
			}
			// If high bits end before or at our region limits:
			// |         v v v v |      v v v v	 |
			// | ... a b c d     |  ... a b c d	 |
			//
			else if ( ( size - dst ) >= it->second.size() )
			{
				// Shift and resize the entry.
				//
				it->second.resize( -dst );
			}
			// Split the region:
			// |       v v       |
			// | ... a b c d ... |
			//
			else
			{
				bitcnt_t low_size = -dst;
				bitcnt_t high_offset = low_size + size;
				bitcnt_t high_size = it->second.size() - high_offset;

				// Split high value.
				//
				value_map.emplace(
					it,
					it->first + ( high_offset / 8 ),
					( it->second >> high_offset ).resize( high_size )
				);

				// Resize low value.
				//
				it->second.resize( low_size );
			}
		}

		// Insert new value.
		//
		return value_map.emplace_back( ptr, value.get() ).second;
	}
};