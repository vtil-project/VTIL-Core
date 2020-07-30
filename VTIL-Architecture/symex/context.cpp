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
#include "context.hpp"

namespace vtil::symbolic
{
	// Returns the absolute mask of known/unknown bits of the given register.
	//
	uint64_t context::known_mask( const register_desc& desc ) const
	{
		// If identifier is not in the store, return false.
		//
		auto it = value_map.find( desc );
		if ( it == value_map.end() )
			return false;

		// Enumerate each bit set within (size+offset, 0]:
		//
		uint64_t known_mask = 0;
		math::bit_enum( it->second.bitmap & math::fill( desc.bit_count + desc.bit_offset ), [ & ] ( bitcnt_t i )
		{
			// If value extends into the region, declare found, set known mask.
			//
			const expression::reference& value = it->second.linear_store[ i ];
			if ( ( value.size() + i ) > desc.bit_offset )
				known_mask |= math::fill( value.size(), i );
		} );
		return known_mask & desc.get_mask();
	}
	uint64_t context::unknown_mask( const register_desc& desc ) const
	{
		return desc.get_mask() & ~known_mask( desc );
	}

	// Reads the value of the given region described by the register desc.
	//  - Will output the mask of bits contained in the state into contains.
	//
	expression::reference context::read( const register_desc& desc, const il_const_iterator& reference_iterator, uint64_t* contains ) const
	{
		uint64_t tmp;
		if ( !contains ) contains = &tmp;

		// If identifier is not in the store, return default.
		//
		auto it = value_map.find( desc );
		if ( it == value_map.end() )
			return *contains = 0, CTX( reference_iterator )[ desc ];

		// Allocate storage for result and create masks.
		//
		uint64_t known_mask = 0;
		uint64_t read_mask = desc.get_mask();
		expression::reference result = nullptr;

		// Enumerate each bit set within (size+offset, 0]:
		//
		math::bit_enum( it->second.bitmap & math::fill( desc.bit_count + desc.bit_offset ), [ & ] ( bitcnt_t i )
		{
			// If value extends into the region:
			//
			const expression::reference& value = it->second.linear_store[ i ];
			if ( ( value.size() + i ) > desc.bit_offset )
			{
				// Set known mask.
				//
				known_mask |= math::fill( value.size(), i );

				// Adjust the value.
				//
				expression::reference adjusted = value;
				if ( i > desc.bit_offset )      adjusted.resize( desc.bit_count ) <<= ( i - desc.bit_offset );
				else if ( i < desc.bit_offset ) adjusted >>= ( desc.bit_offset - i ), adjusted.resize( desc.bit_count );
				else                            adjusted.resize( desc.bit_count );

				// Append to the result.
				//
				if ( result ) result |= std::move( adjusted );
				else          result =  std::move( adjusted );
			}
		} );

		// If no bits set in known mask, return default.
		//
		*contains = known_mask & read_mask;
		if ( !*contains )
			return CTX( reference_iterator )[ desc ];

		// If all bits set in known mask, return as is.
		//
		if ( ( known_mask & read_mask ) == read_mask )
			return result;

		// Or with the bits that we do not know and return.
		//
		return result | ( variable{ reference_iterator, desc.select( 64, 0 ) }.to_expression() & ( read_mask & ~known_mask ) ) >> desc.bit_offset;
	}

	// Writes the given value to the region described by the register desc.
	//
	void context::write( const register_desc& desc, expression::reference value )
	{
		// Find the register in the map and determine limit of the descriptor.
		//
		auto& context = value_map[ desc ];
		bitcnt_t reg_end = desc.bit_count + desc.bit_offset;

		// Push left  (size+offset, offset].
		//
		math::bit_enum( context.bitmap & desc.get_mask(), [ & ] ( bitcnt_t i )
		{
			// Reset the bit, and move the value.
			//
			expression::reference stored_value = std::exchange( context.linear_store[ i ], nullptr );
			bitcnt_t value_end = stored_value.size() + i;
			math::bit_reset( context.bitmap, i );

			// If value extends beyond the region we're overwriting:
			//
			if ( value_end > reg_end )
			{
				// Shift the value and place it at the border.
				//
				auto& ref = context.linear_store[ reg_end ];
				dassert( !ref );

				ref = std::move( stored_value ) >> ( reg_end - i );
				ref.resize( value_end - reg_end );
				math::bit_set( context.bitmap, reg_end );
			}
		} );

		// Push right (offset,           0].
		//
		math::bit_enum( context.bitmap & math::fill( desc.bit_offset, 0 ), [ & ] ( bitcnt_t i )
		{
			// If value extends into the region we're overwriting:
			//
			expression::reference& stored_value = context.linear_store[ i ];
			bitcnt_t value_end = stored_value.size() + i;

			if ( value_end > desc.bit_offset )
			{
				// If value extends beyond the region we're overwriting:
				//
				if ( value_end > reg_end )
				{
					auto& ext = context.linear_store[ reg_end ];
					dassert( !ext );

					ext = stored_value >> ( reg_end - i );
					ext.resize( value_end - reg_end );
					math::bit_set( context.bitmap, reg_end );
				}

				// Resize the value.
				//
				stored_value.resize( desc.bit_offset - i );
			}
		} );

		// Write the value.
		//
		value.resize( desc.bit_count );
		
		auto& res = context.linear_store[ desc.bit_offset ];
		dassert( !res );

		res = std::move( value );
		math::bit_set( context.bitmap, desc.bit_offset );
	}
};
