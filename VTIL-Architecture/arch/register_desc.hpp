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
#include <string>
#include <vtil/math>
#include <vtil/utility>
#include <vtil/amd64> // TODO: Remove me.

namespace vtil
{
	// Flags that describe the properties of the register.
	//
	enum register_flag : uint32_t
	{
		// Default value if no flags set, R/W pure virtual register that is not a stack pointer or flags.
		// - (!) Do not use as a flag, this is just here as a syntax sugar.
		//
		register_virtual =               0,

		// Indicates that it is a physical register.
		//
		register_physical =         1 << 0,

		// Indicates that it is a local temporary register of the current basic block.
		//
		register_local =            1 << 1,

		// Indicates that it is used to hold CPU flags.
		//
		register_flags =            1 << 2,

		// Indicates that it is used as the stack pointer.
		//
		register_stack_pointer =    1 << 3,

		// Indicates that it is an alias to the image base.
		//
		register_image_base =       1 << 4,

		// Indicates that it can change spontanously. (Say, IA32_TIME_STAMP_COUNTER.)
		//
		register_volatile =         1 << 5,
		register_readonly =         1 << 6,

		// Indicates that it is the special "undefined" register.
		//
		register_undefined =        1 << 7,

		// Indicates that it is a internal-use register that should be 
		// treated like any other virtual register.
		//
		register_internal =         register_virtual |  ( 1 << 8 ),

		// Combined mask of all special registers.
		//
		register_special =          register_flags | 
		                            register_stack_pointer | 
		                            register_image_base |
		                            register_undefined,
	};

	// This type describes any register instance.
	//
	struct register_desc : reducable<register_desc>
	{
		// Flags of the current register, as described in "enum register_flag".
		//
		uint32_t flags;

		// Arbitrary identifier, is intentionally not universally unique to let ids of user registers make use
		// of the full 64-bit range as otherwise we'd have to reserve some magic numbers for flags and stack pointer. 
		// Due to this reason, flags should also be compared when doing comparison.
		//
		size_t local_id;
		
		// Size of the register in bits.
		//
		bitcnt_t bit_count = 0;

		// Offset at which we read from the full 64-bit version.
		//
		bitcnt_t bit_offset;

		// Default constructor / move / copy.
		//
		register_desc() = default;
		register_desc( register_desc&& ) = default;
		register_desc( const register_desc& ) = default;
		register_desc& operator=( register_desc&& ) = default;
		register_desc& operator=( const register_desc& ) = default;

		// Construct a fully formed register.
		//
		register_desc( uint32_t flags, size_t id, bitcnt_t bit_count, bitcnt_t bit_offset = 0 )
			: flags( flags ), local_id( id ), bit_count( bit_count ), bit_offset( bit_offset ) 
		{ 
			fassert( is_valid() ); 
		}

		// Returns whether the descriptor is valid or not.
		//
		bool is_valid() const 
		{ 
			// Validate bit count and offset.
			//
			if ( bit_count == 0 || ( bit_count + bit_offset ) > 64 )
				return false;

			// Handle special registers:
			//
			uint32_t special_flags = flags & register_special;

			// If register holds the stack pointer:
			//
			if ( special_flags == register_stack_pointer )
			{
				// Should be physical, non-volatile and writable.
				//
				if ( is_volatile() || is_read_only() || !is_physical() )
					return false;

				// Must have no local identifier.
				//
				if ( local_id != 0 )
					return false;
			}
			// If register holds the flags:
			//
			else if ( special_flags == register_flags )
			{
				// Should be physical, non-volatile and writable.
				//
				if ( is_volatile() || is_read_only() || !is_physical() )
					return false;

				// Must have no local identifier.
				//
				if ( local_id != 0 )
					return false;
			}
			// If register holds the image base:
			//
			else if ( special_flags == register_image_base )
			{
				// Should be virtual, non-volatile and read-only.
				//
				if ( is_volatile() || !is_virtual() || !is_read_only() )
					return false;

				// Must have no local identifier.
				//
				if ( local_id != 0 )
					return false;
			}
			// If register holds the [undefined] special:
			//
			else if ( special_flags == register_undefined )
			{
				// Should be virtual, volatile and non-read-only.
				//
				if ( !is_volatile() || !is_virtual() || is_read_only() )
					return false;

				// Must have no local identifier.
				//
				if ( local_id != 0 )
					return false;
			}
			// Otherwise must have no special flags.
			//
			else if( special_flags != 0 )
			{
				return false;
			}

			// If register is physical, it can't be local.
			//
			return !is_physical() || !is_local();
		}

		// Simple helpers to determine some properties.
		// 
		bool is_flags() const { return flags & register_flags; }
		bool is_undefined() const { return flags & register_undefined; }
		bool is_local() const { return flags & register_local; }
		bool is_global() const { return ( ~flags ) & register_local; }
		bool is_virtual() const { return ( ~flags ) & register_physical; }
		bool is_physical() const { return flags & register_physical; }
		bool is_volatile() const { return flags & register_volatile; }
		bool is_read_only() const { return flags & register_readonly; }
		bool is_stack_pointer() const { return flags & register_stack_pointer; }
		bool is_image_base() const { return flags & register_image_base; }
		bool is_special() const { return flags & register_special; }
		bool is_internal() const { return ( flags & register_internal ) == register_internal; }

		// Returns the mask for the bits that this register's value would occupy in a 64-bit register.
		//
		uint64_t get_mask() const { return math::fill( bit_count, bit_offset ); }

		// Checks whether bits from this register and the other register overlap.
		//
		bool overlaps( const register_desc& o ) const 
		{ 
			if ( local_id != o.local_id || flags != o.flags ) 
				return false;
			return get_mask() & o.get_mask();
		}

		// Conversion to human-readable format.
		// - Note: Do not move this to a source file since we want the template we're using to be overriden!
		//
		std::string to_string() const 
		{ 
			// Prefix with the properties.
			//
			std::string prefix = "";
			if ( flags & register_volatile ) prefix = "?";
			if ( flags & register_readonly ) prefix += "&&";
			
			// Suffix with the offset (omit if 0) and bit-count (omit if 64).
			//
			std::string suffix = "";
			if ( bit_offset != 0 ) suffix = "@" + std::to_string( bit_offset );
			if ( bit_count != 64 ) suffix += ":" + std::to_string( bit_count );

			// If special/local, use a fixed convention.
			//
			if ( is_internal() )                  return prefix + "sr" + std::to_string( local_id ) + suffix;
			if ( flags & register_undefined )     return prefix + "UD" + suffix;
			if ( flags & register_flags )         return prefix + "$flags" + suffix;
			if ( flags & register_stack_pointer ) return prefix + "$sp" + suffix;
			if ( flags & register_image_base )    return prefix + "base" + suffix;
			if ( flags & register_local )         return prefix + "t" + std::to_string( local_id ) + suffix;

			// Otherwise use the default naming.
			//
			if ( ( flags & register_physical ) )
				#pragma warning(suppress: 4267)
				return prefix + amd64::name( amd64::extend( local_id ) ) + suffix;
			else
				return prefix + "vr" + std::to_string( local_id ) + suffix;
		}

		// Declare reduction.
		//
		auto reduce() { return reference_as_tuple( bit_count, local_id, flags, bit_offset ); }

		// TODO: Remove me.
		//  Let modern compilers know that we use these operators as is,
		//  implementation considering all candidates would be preferred
		//  but since not all of our target compilers implement complete
		//  ISO C++20, we have to go with this "patch".
		//
		using reducable::operator<;
		using reducable::operator==;
		using reducable::operator!=;
	};

	// Should be overriden by the user to describe conversion of the
	// register type they use (e.g. x86_reg for Capstone/Keystone) into
	// VTIL register descriptors for seamless casting into vtil::operand type.
	//
	template<typename T>
	struct register_cast
	{
		register_desc operator()( const T& value )
		{
			static_assert( sizeof( T ) == -1, "Failed to cast given operand into a register type." );
			return {};
		}
	};
	template<> 
	struct register_cast<register_desc>
	{
		template<typename T>
		auto operator()( T&& v ) { return std::forward<T>( v ); }
	};

	// VTIL special registers.
	//
	static const register_desc UNDEFINED =   { register_volatile | register_undefined,     0, 64 };
	static const register_desc REG_IMGBASE = { register_readonly | register_image_base,    0, 64 };
	static const register_desc REG_FLAGS =   { register_physical | register_flags,         0, 64 };
	static const register_desc REG_SP =      { register_physical | register_stack_pointer, 0, 64 };
};