#pragma once
#include <string>
#include <array>
#include "..\io\formatting.hpp"

namespace vtil
{
	// Defines a 128-bit hash type based on FNV-1.
	//
	class fnv128_hash_t
	{
		// Magic constants for 128-bit FNV-1 .
		//
		using value_t = std::array<size_t, 2>;
		static constexpr value_t default_seed = { 0x6C62272E07BB0142, 0x62B821756295C58D };
		static constexpr value_t prime =        { 0x0000000001000000, 0x000000000000013B };

		// Current value of the hash.
		//
		value_t value;

		public:
		// Construct a new hash from an optional seed of either 64-bit or 128-bit value.
		//
		fnv128_hash_t( size_t seed64 ) : value( { ~0ull, seed64 } ) {}
		fnv128_hash_t( value_t seed128 = default_seed ) : value( seed128 ) {}

		// Append the given item into hash.
		//
		template<typename T>
		fnv128_hash_t& operator<<( const T& item )
		{
			// Parse the item as an array of bytes.
			//
			auto& bytes = ( const uint8_t( & )[ sizeof( T ) ] ) item;

			// Apply the FNV-1 algorithm and return self-reference.
			//
			for ( uint8_t byte : bytes )
			{
				// Apply XOR over the low byte.
				//
				value[ 0 ] ^= byte;

				// Calculate [value * prime].
				//
				// A: 0x???????????????? 0x????????????????
				//                    HA                 LA
				uint64_t ha = value[ 1 ], la = value[ 0 ];
				// B: 0x0000000001000000 0x000000000000013B
				//                    HB                 LB
				uint64_t hb = prime[ 1 ], lb = prime[ 0 ];
				//                                        x
				// ----------------------------------------
				// = (HA<<64 + LA) * (HB<<64 + LB)
				//
				// = LA     * LB       (Has both low and high parts)
				//
				value[ 0 ] = _umul128( la, lb, &value[ 1 ] );
				//
				//   HA<<64 * HB<<64 + (Discarded)
				//   HA<<64 * LB     + (Will have no low part)
				//
				value[ 1 ] += ha * lb;
				//
				//   LA     * HB<<64 + (Will have no low part)
				//
				value[ 1 ] += la * hb;
			}

			// Return a self-reference.
			//
			return *this;
		}

		// Implicit conversion to 64-bit and 128-bit values.
		//
		size_t as64() const { return value[ 0 ] + value[ 1 ]; }
		value_t as128() const { return value; }
		operator size_t() const { return as64(); }
		operator value_t() const { return as128(); }

		// Conversion to human-readable format.
		//
		std::string to_string() const
		{
			return format::str( "0x%p%p", value[ 1 ], value[ 0 ] );
		}

		// Basic comparison operators.
		//
		bool operator<( const fnv128_hash_t& o ) const { return value < o.value; }
		bool operator==( const fnv128_hash_t& o ) const { return value == o.value; }
		bool operator!=( const fnv128_hash_t& o ) const { return value != o.value; }
	};
};

// Make it std::hashable.
//
namespace std
{
	template<>
	struct hash<vtil::fnv128_hash_t>
	{
		size_t operator()( const vtil::fnv128_hash_t& value ) const { return value; }
	};
};