#pragma once
#include <string>
#include <capstone.hpp>
#include "..\misc\format.hpp"
#include "register_details.hpp"

namespace vtil::arch
{
	// Register descriptors are used to describe each unique "full" register such as RAX. 
	// Any physical register such as EAX will be extended to its full form (RAX in this case).
	// - Note: Size of a register is always assumed to be 64-bits.
	//
	struct register_desc
	{
		// Descriptor's identifier will be used for comparison if the register 
		// instance is not mapped to any physical register.
		//
		std::string identifier = "";
		
		// If this field is not X86_REG_INVALID, it's an indicator that this
		// register and the alias essentially maps to a physical register.
		//
		x86_reg maps_to = X86_REG_INVALID;

		// Either a x86 register identifier or an arbitrary string must be passed
		// to construct a register descriptor.
		//
		register_desc() {}
		register_desc( x86_reg reg ) { maps_to = extend_register( reg ); identifier = name_register( maps_to ); }
		register_desc( const std::string& id ) : identifier( id ) {}

		// Conversion to human-readable format.
		//
		std::string to_string() const { return identifier; }

		// Simple helpers to determine the type of register.
		//
		bool is_physical() const { return maps_to != X86_REG_INVALID; }
		bool is_valid() const { return !identifier.empty(); }

		// Basic comparison operators.
		//
		bool operator!=( const register_desc& o ) const { return !operator==( o ); }
		bool operator==( const register_desc& o ) const { return identifier == o.identifier; }
		bool operator<( const register_desc& o ) const { return identifier < o.identifier; }
	};

	// Register views are used to describe well-defined segments of registers.
	// - AX views RAX @ {0, 2}, BH views RBX @ {1, 1} so on. 
	//
	struct register_view
	{
		// The base register descriptor.
		//
		register_desc base = {};

		// Offset into that register and the segment referenced.
		//
		uint8_t offset = 0;
		uint8_t size = 8;

		// Basically an extended version of the register descriptor constructor
		// with the addition of an offset and a size value.
		//
		register_view() {}
		register_view( x86_reg base, uint8_t offset = 0, uint8_t size = 8 ) : base( base ), size( size ), offset( offset ) { fassert( is_valid() ); }
		register_view( const std::string& base, uint8_t offset = 0, uint8_t size = 8 ) : base( base ), size( size ), offset( offset ) { fassert( is_valid() ); }
		register_view( const register_desc& base, uint8_t offset = 0, uint8_t size = 8 ) : base( base ), size( size ), offset( offset ) { fassert( is_valid() ); }

		// Mask that describes how we map to the base register and a
		// basic "overlapping" check using this mask.
		//
		uint64_t get_mask() const { return ( ~0ull >> ( 64 - size * 8 ) ) << ( offset * 8 ); }
		bool overlaps( const register_view& o )  const { return base == o.base && ( get_mask() & o.get_mask() ); }

		// Conversion to human-readable format.
		//
		std::string to_string( bool explicit_size = false ) const
		{
			if ( base.is_physical() )
				return name_register( remap_register( base.maps_to, offset, size ) );
			std::string out = base.identifier;
			if ( explicit_size && size != 8 )
				out += format::suffix_map[ size ];
			if ( offset != 0 )
				out += "@" + std::to_string( offset );
			return out;
		}

		// Validity check.
		//
		bool is_valid() const { return base.is_valid() && ( offset + size ) <= 8; }

		// Basic comparison operators.
		//
		bool operator!=( const register_view& o ) const { return !operator==( o ); };
		bool operator==( const register_view& o ) const { return base.identifier == o.base.identifier && offset == o.offset && size == o.size; }
		bool operator<( const register_view& o ) const { return base.identifier == o.base.identifier ? ( offset == o.offset ? size < o.size : offset < o.offset ) : base.identifier < o.base.identifier; }
	};
};