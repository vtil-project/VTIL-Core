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
#include <type_traits>
#include <optional>

namespace vtil
{
	// Replicates the expected behaviour of std::optional<T&>.
	//
	template<typename T>
	struct optional_reference
	{
		T* pointer = nullptr;

		// Null reference constructors.
		//
		constexpr optional_reference( std::nullopt_t ) : pointer( nullptr ) {}
		
		// Constructs by reference to type.
		//
		constexpr optional_reference( T& ref )                       : pointer( &ref ) {}
		constexpr optional_reference( std::optional<T>& ref )        : pointer( ref.has_value() ? &ref.value() : nullptr ) {}
		// -- Lifetime must be guaranteed by the caller.
		constexpr optional_reference( T&& ref ) : pointer( &ref ) {}
		constexpr optional_reference( std::optional<T>&& ref ) : pointer( ref.has_value() ? &ref.value() : nullptr ) {}
		
		// Default constructor / move / copy.
		//
		constexpr optional_reference() = default;
		constexpr optional_reference( optional_reference&& ) = default;
		constexpr optional_reference( const optional_reference& ) = default;
		constexpr optional_reference& operator=( optional_reference&& ) = default;
		constexpr optional_reference& operator=( const optional_reference& ) = default;

		// Optional assignment to reference stored.
		//
		constexpr void assign_if( T&& value ) { if ( pointer ) *pointer = value; }
		constexpr void assign_if( const T& value ) { if ( pointer ) *pointer = value; }

		// Implement observers, mimicking std::optional<T>.
		// -------------------------------------------------
		// Accesses the contained value.
		//
		constexpr T& value() { return *pointer; }
		constexpr T& value() const { return *pointer; }
		constexpr T value_or( const T& def ) const { return has_value() ? value() : def; }
		constexpr T& value_or( std::remove_const_t<T>& def ) const { return has_value() ? value() : def; }
		constexpr T& operator*() { return value(); }
		constexpr T& operator*() const { return value(); }
		constexpr T* operator->() { return pointer; }
		constexpr T* operator->() const { return pointer; }

		// Checks whether the object contains a value.
		//
		constexpr bool has_value() const { return pointer != nullptr; }
		constexpr explicit operator bool() const { return has_value(); }

		// Implement modifiers, mimicking std::optional<T>.
		// -------------------------------------------------
		// Destroys currently held reference.
		//
		constexpr void reset() { pointer = nullptr; }

		// Constructs the contained value in-place.
		//
		constexpr void emplace( T& ref ) { pointer = &ref; }

		// Decays the reference to a constant qualified instance.
		//
		constexpr operator optional_reference<const T>() const { return { pointer }; }

		// Decay to reference, if no value held UB.
		//
		constexpr operator T& () { return *( T* ) pointer; }
		constexpr operator const T& () const { return *( T* ) pointer; }
	};
	template<typename T>
	using optional_creference = optional_reference<const T>;

	// Creates an optional reference to the given pointer if the condition is met.
	//
	template<typename T>
	static constexpr auto dereference_if( bool condition, T ptr )
	{
		return condition ? optional_reference( *ptr ) : std::nullopt;
	}

	template<typename T>
	static constexpr auto dereference_if_n( bool condition, T ptr, size_t idx )
	{
		return condition ? optional_reference{ *( ptr + idx ) } : std::nullopt;
	}
};

// Overload hasher for vtil::optional_reference<>.
//
namespace std
{
	// Same implementation as std::hash<std::optional<T>>.
	//
	template<typename T>
	struct hash<vtil::optional_reference<T>>
	{
		size_t operator()( const vtil::optional_reference<T>& value ) const noexcept
		{
			return value ? std::hash<T>{}( *value ) : 0;
		}
	};
};