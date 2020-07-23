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
#pragma once
#include <stdint.h>
#include <optional>
#include "../io/asserts.hpp"
#include "../io/formatting.hpp"

namespace vtil
{
	// A generic 3 value logic wrapper since it is a common pattern.
	//
	struct trilean
	{
		// Implement the trilean literal unknown and null.
		//
		struct null_t {};
		struct unknown_t {};
		static constexpr null_t null =       {};
		static constexpr unknown_t unknown = {};

		// +1 - true
		// 0  - ? 
		// -1 - false
		//
		int8_t value = 0;
											       
		// Constructor for known boolean.	       
		//									       
		constexpr trilean( bool boolean )          : value( boolean - !boolean ) {}

		// Constructor for unknown.
		//
		constexpr trilean( unknown_t )             : value( 0 ) {}

		// Constructor for null (alias for false).
		//
		constexpr trilean( null_t )                : trilean( false ) {}

		// Default copy move.
		//
		constexpr trilean( trilean&& ) = default;
		constexpr trilean( const trilean& ) = default;
		constexpr trilean& operator=( trilean&& ) = default;
		constexpr trilean& operator=( const trilean& ) = default;

		// Mimic std::optional interface.
		//
		constexpr bool has_value() const { return value != 0; }
		constexpr bool value_or( bool o ) const { return ( value + o ) > 0; }

		// Syntax sugar for "value or true".
		//
		constexpr bool operator+() const { return value >= 0; }

		// Syntax sugar for "value or false".
		//
		constexpr bool operator-() const { return value <= 0; }

		// operator! checks for false, whereas operator bool checks for true.
		//
		constexpr bool operator!() const { return value == -1; }
		constexpr explicit operator bool() const { return value == 1; }

		// Comparison with boolean.
		//
		constexpr bool operator==( bool boolean ) const { return value == ( boolean - !boolean ); }
		constexpr bool operator!=( bool boolean ) const { return value != ( boolean - !boolean ); }

		// Comparison with trilean.
		//
		constexpr bool operator==( trilean other ) const { return value == other.value; }
		constexpr bool operator!=( trilean other ) const { return value != other.value; }

		// Cast to string.
		//
		std::string to_string() const
		{
			switch ( value )
			{
				case -1: return "False";
				case 0:  return "Unknown";
				case +1: return "True";
			}
			unreachable();
		}
	};

	// Base class uncertain inherits from.
	//
	struct uncertain_t
	{
		// Inherit the trilean literal unknown and null.
		//
		using null_t =    trilean::null_t;
		using unknown_t = trilean::unknown_t;
		static constexpr null_t null = {};
		static constexpr unknown_t unknown = {};
	};

	// std::optional like type with trilean state.
	//
	template<typename T = std::nullopt_t>
	struct uncertain : uncertain_t
	{
		// The actual optional value stored and if nullopt, whether it is in a certain state.
		//
		std::optional<T> value;
		bool is_certain;

		// Constructs null.
		//
		constexpr uncertain()                         : is_certain( true ),  value( std::nullopt ) {}
		constexpr uncertain( std::nullopt_t )         : is_certain( true ),  value( std::nullopt ) {}
		constexpr uncertain( null_t )                 : is_certain( true ),  value( std::nullopt ) {}

		// Constructs unknown.
		//
		constexpr uncertain( unknown_t )              : is_certain( false ), value( std::nullopt ) {}

		// Construct definite value.
		//
		constexpr uncertain( T value )                : is_certain( true ),  value( std::move( value ) ) {}
		constexpr uncertain( std::optional<T> value ) : is_certain( true ),  value( std::move( value ) ) {}

		// Default copy/move.
		//
		constexpr uncertain( uncertain&& ) = default;
		constexpr uncertain( const uncertain& ) = default;
		constexpr uncertain& operator=( uncertain&& ) = default;
		constexpr uncertain& operator=( const uncertain& ) = default;
		
		// Cast to trilean.
		//
		constexpr trilean state() const
		{
			if ( has_value() )       return true;
			if ( is_certain )        return false;
			else                     return unknown;
		}
		constexpr operator trilean() const           { return state(); }
		constexpr bool operator==( null_t ) const    { return is_null(); }
		constexpr bool operator==( unknown_t ) const { return is_unknown(); }
		constexpr bool operator==( trilean o ) const { return o == state(); }

		// Boolean negation operator checks for certain inexistance, whereas explicit bool cast checks for 
		// certain existance, they both will return false if it's in an unknown state.
		//
		constexpr bool operator!() const         { return is_null(); }
		constexpr explicit operator bool() const { return has_value(); }

		// std::optional like state checking.
		//
		constexpr bool is_null() const    { return is_certain && !value.has_value(); }
		constexpr bool has_value() const  { return value.has_value(); }
		constexpr bool is_unknown() const { return !is_certain; }

		// Access to value via deref / use as pointer.
		//
		constexpr auto& get()              { return value.value(); }
		constexpr auto& get() const        { return value.value(); }
		constexpr auto& operator*()        { return value.value(); }
		constexpr auto& operator*() const  { return value.value(); }
		constexpr auto* operator->()       { return &value.value(); }
		constexpr auto* operator->() const { return &value.value(); }

		// Cast to string.
		//
		std::string to_string() const
		{
			if ( has_value() )       return format::as_string( get() );
			else if ( is_certain )   return "[Null]";
			else                     return "[Unknown]";
		}
	};

	// Mimic std::make_optional, unline uncertain(...) constructor will default to unknown 
	// when no arguments are passed instead of defaulting to certain null.
	//
	template<typename T> static constexpr uncertain<T> make_uncertain()          { return uncertain<T>::unknown; }
	template<typename T> static constexpr uncertain<T> make_uncertain( T value ) { return uncertain<T>{ std::move( value ) }; }
};