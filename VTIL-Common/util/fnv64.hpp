#pragma once
#include <string>
#include <array>
#include "..\io\formatting.hpp"

namespace vtil
{
	// Defines a 64-bit hash type based on FNV-1.
	//
	class fnv64_hash_t
	{
		// Magic constants for 64-bit FNV-1 .
		//
		using value_t = size_t;
		static constexpr size_t default_seed = { 0xCBF29CE484222325 };
		static constexpr size_t prime =        { 0x00000100000001B3 };

		// Current value of the hash.
		//
		value_t value;

		public:
		// Construct a new hash from an optional seed of 64-bit value.
		//
		fnv64_hash_t( value_t seed64 = default_seed ) : value( seed64 ) {}

		// Append the given item into hash.
		//
		template<typename T>
		fnv64_hash_t& operator<<( const T& item )
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
				value ^= byte;

				// Calculate [value * prime].
				//
				value *= prime;
			}

			// Return a self-reference.
			//
			return *this;
		}

		// Implicit conversion to 64-bit values.
		//
		size_t as64() const { return value; }
		operator size_t() const { return as64(); }

		// Conversion to human-readable format.
		//
		std::string to_string() const
		{
			return format::str( "0x%p", value );
		}

		// Basic comparison operators.
		//
		bool operator<( const fnv64_hash_t& o ) const { return value < o.value; }
		bool operator==( const fnv64_hash_t& o ) const { return value == o.value; }
		bool operator!=( const fnv64_hash_t& o ) const { return value != o.value; }
	};
};

// Make it std::hashable.
//
namespace std
{
	template<>
	struct hash<vtil::fnv64_hash_t>
	{
		size_t operator()( const vtil::fnv64_hash_t& value ) const { return value; }
	};
};