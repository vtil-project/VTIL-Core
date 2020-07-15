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

namespace vtil
{
	// A generic 3 value logic wrapper since it is a common pattern.
	//
	union trilean
	{
		struct by_value {};

		// +1 - true
		// 0  - ? 
		// -1 - false
		//
		int8_t value = 0;

		// Constructor for "maybe".
		//
		constexpr trilean()                          : value( 0 ) {}
											       
		// Constructor for strong boolean.	       
		//									       
		constexpr trilean( bool boolean )            : value( boolean - !boolean ) {}

		// Explicit construction from integer.
		//
		constexpr trilean( int8_t value, by_value )  : value( value ) {}

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

		// Negation.
		//
		constexpr trilean operator!() const { return { -value, by_value{} }; }

		// Comparison with boolean.
		//
		constexpr bool operator==( bool boolean ) const { return value == ( boolean - !boolean ); }
		constexpr bool operator!=( bool boolean ) const { return value != ( boolean - !boolean ); }

		// Comparison with trilean.
		//
		constexpr bool operator==( trilean other ) const { return value == other.value; }
		constexpr bool operator!=( trilean other ) const { return value != other.value; }
	};

	// Namespace for trilean literals.
	//
	namespace trilean_literals
	{
		static constexpr trilean Maybe = {};
		static constexpr trilean True  = { true };
		static constexpr trilean False = { false };
	};

	// By default, included in VTIL namespace.
	//
	using namespace trilean_literals;
};