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
#include <functional>
#include <stdint.h>
#include <cstring>
#include <optional>
#include "vtype_traits.hpp"
#include "../io/asserts.hpp"
#include "../io/logger.hpp"

// [Configuration]
// Determine the maximum size of types we should inline.
//
#ifndef VTIL_VARIANT_INLINE_LIMIT
	#define VTIL_VARIANT_INLINE_LIMIT 0x70
#endif

namespace vtil
{
	// Variant can be used to store values of any type in a fast way.
	//
	#pragma pack(push, 1)
	struct alignas( 8 ) variant
	{
		// Value is either stored in the [char inl[]] as an inline object,
		// or in [void* ext] as an external pointer.
		//
		union
		{
			char inl[ VTIL_VARIANT_INLINE_LIMIT ];
			void* ext;
		};

		// Virtual traits.
		//
		const vtype_traits_t* traits;

		// Set if object is inlined:
		//
		bool is_inline;

		// Null constructors.
		//
		variant() : traits( nullptr ) {};
		variant( std::nullopt_t ) : traits( nullptr ) {};

		// Constructs variant from any type that is not variant, nullptr_t or nullopt_t.
		//
		template<typename arg_type, 
			std::enable_if_t<
			 !std::is_same_v<std::decay_t<arg_type>, variant> &&
			 !std::is_same_v<std::decay_t<arg_type>, std::nullopt_t>, int> = 0>
		variant( arg_type&& value )
		{
			using T = std::remove_cvref_t<arg_type>;
			static_assert( alignof( T ) <= 8, "Object aligned over max alignment." );

			// Invoke constructor on allocated space.
			//
			T* out = new ( allocate( sizeof( T ) ) ) T( std::forward<arg_type>( value ) );

			// Assign generic actor.
			//
			traits = vtype_traits_v<T>;
		};

		// Copy/move constructors.
		//
		variant( const variant& src );
		variant( variant&& vo );

		// Assignment operators.
		//
		variant& operator=( variant&& vo );
		variant& operator=( const variant& o );

		// Variant does not have a value if the traits are null.
		//
		bool has_value() const { return traits != nullptr; }
		operator bool() const { return has_value(); }

		// Gets the address of the object with the given properties.
		//
		void* get_address() { return is_inline ? ( void* ) &inl[ 0 ] : ( void* ) ext; }
		const void* get_address() const { return make_mutable( this )->get_address(); }

		// Allocates the space for an object of the given properties and returns the pointer.
		//
		void* allocate( size_t size );

		// Simple wrappers around get_address.
		// - Will throw assert failure if the variant is empty.
		//
		template<typename T>
		T& get() 
		{
			// Validate type equivalence and existance.
			//
			fassert( traits == vtype_traits_v<T> );

			// Calculate the address and return a reference.
			//
			return *( T* ) get_address(); 
		}
		template<typename T>
		const T& get() const 
		{
			// Validate type equivalence and existance.
			//
			fassert( traits == vtype_traits_v<T> );

			// Calculate the address and return a const qualified reference.
			//
			return *( const T* ) get_address(); 
		}

		// Cast to optional.
		// - Unlike ::get, will not throw an assert failure if the variant
		//   is empty and will return nullopt instead.
		//
		template<typename T>
		std::optional<T> as() const { return has_value() ? std::optional{ get<T>() } : std::nullopt; }

		// Deletes the currently stored variant.
		//
		void reset();
		 ~variant() { reset(); }
	};
	#pragma pack(pop)
};