#pragma once
#include <stdint.h>
#include <array>

namespace vtil
{
	// Initialize default random seed from __TIME__ macro.
	//
	static constexpr uint64_t crandom_default_seed = ([]()
	{
		uint64_t value = 0xa0d82d3adc00b109;
		for ( char c : __TIME__ )
			value = ( value ^ c ) * 0x100000001B3;
		return value;
	} )();

	// Linear congruential generator using the constants from Numerical Recipes.
	//
	static constexpr uint64_t lce_64( uint64_t& value )
	{
		return ( value = 1664525 * value + 1013904223 );
	}

	// Generates a single u64 random number,  optionally skipping the first N numbers based on the offset given.
	//
	static constexpr uint64_t make_crandom( size_t offset = 0 )
	{
		uint64_t value = crandom_default_seed;
		while ( offset-- != 0 ) lce_64( value );
		return lce_64( value );
	}

	// Generates N u64 random numbers, optionally skipping the first N numbers based on the offset given.
	//
	template<size_t... I>
	static constexpr std::array<size_t, sizeof...( I )> make_crandom_n( size_t offset, std::index_sequence<I...> )
	{
		uint64_t value = offset ? make_crandom( offset - 1 ) : crandom_default_seed;
		return { lce_64( ( I, value ) )... };
	}
	template<size_t N>
	static constexpr auto make_crandom_n( size_t offset = 0 )
	{
		return make_crandom_n( offset, std::make_index_sequence<N>{} );
	}
};