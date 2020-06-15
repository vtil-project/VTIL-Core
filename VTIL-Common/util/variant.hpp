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
#include <type_traits>
#include <functional>
#include <stdint.h>
#include <cstring>
#include <optional>
#include "../io/asserts.hpp"

// [Configuration]
// Determine whether we should use safe variants or not.
//
#if _DEBUG && not defined(VTIL_VARIANT_SAFE)
	#if defined(_CPPRTTI)
		#define VTIL_VARIANT_SAFE	_CPPRTTI
	#elif defined(__GXX_RTTI)
		#define VTIL_VARIANT_SAFE	__GXX_RTTI
	#elif defined(__has_feature)
		#define VTIL_VARIANT_SAFE	__has_feature(cxx_rtti)
	#else
		#define VTIL_VARIANT_SAFE	0
	#endif
#elif defined(VTIL_VARIANT_SAFE) && VTIL_VARIANT_SAFE
	#error Debug mode binaries cannot use RTTI based variant safety checks.
#endif

// [Configuration]
// Determine the maximum size of types we should inline.
//
#ifndef VTIL_VARIANT_INLINE_LIMIT
	#define VTIL_VARIANT_INLINE_LIMIT 0x100
#endif

namespace vtil
{
	// Variant can be used to store values of any type in a fast way.
	//
	#pragma pack(push, 1)
	struct variant
	{
		// Value is either stored in the [char inl[]] as an inline object,
		// or in [void* ext] as an external pointer.
		//
		union
		{
			char inl[ VTIL_VARIANT_INLINE_LIMIT ];
			void* ext;
		};

		// Set if object is inlined:
		//
		uint8_t is_inline : 1;

		// Set if object has a trivial copy constructor.
		//
		uint8_t is_trivial_copy : 1;

		// Details of copy constructor:
		//
		union
		{
			// If trivial, size and the alignment of the object.
			//
			struct
			{
				uint64_t copy_size : 32;
				uint64_t copy_align : 32;
			};

			// Otherwise pointer to helper.
			//
			void( *copy_fn )( const variant&, variant& );
		};

		// Destructor callback.
		//
		void( *destroy_fn )( variant& );

		// If debug mode, currently assigned typeid's name or undefined if RTTI is disabled.
		//
#ifdef _DEBUG
		const char* __typeid_name;
#endif

		// Null constructors.
		//
		variant() : copy_fn( nullptr ) {};
		variant( std::nullptr_t ) : copy_fn( nullptr ) {};
		variant( std::nullopt_t ) : copy_fn( nullptr ) {};

		// Constructs variant from any type that is not variant, nullptr_t or nullopt_t.
		//
		template<typename arg_type, 
			std::enable_if_t<
			 !std::is_same_v<std::remove_cvref_t<arg_type>, variant> &&
			 !std::is_same_v<std::remove_cvref_t<arg_type>, std::nullptr_t> &&
			 !std::is_same_v<std::remove_cvref_t<arg_type>, std::nullopt_t>, int> = 0>
		variant( arg_type&& value )
		{
			using T = std::remove_cvref_t<arg_type>;

			// Invoke copy constructor on allocated space.
			//
			T* out = new ( allocate( sizeof( T ), alignof( T ) ) ) T( std::forward<arg_type>( value ) );

			// Assign destructor if not trivially destructible.
			//
			if constexpr ( !std::is_trivially_destructible_v<T> )
				destroy_fn = [ ] ( variant& v ) { v.get<T>().~T(); };
			// Otherwise null the destroy callback.
			//
			else
				destroy_fn = nullptr;

			// Assign copy constructor if not trivially copyable.
			//
			if constexpr ( !std::is_trivially_copyable_v<T> )
			{
				copy_fn = [ ] ( const variant& src, variant& dst )
				{
					new ( dst.allocate( sizeof( T ), alignof( T ) ) ) T( src.get<T>() );
				};
				is_trivial_copy = false;
			}
			// Otherwise indicate trivial copy.
			//
			else
			{
				copy_size = sizeof( T );
				copy_align = alignof( T );
				is_trivial_copy = true;
			}

			// If safe mode, assign type name.
			//
#if VTIL_VARIANT_SAFE
			__typeid_name = typeid( T ).name();
#endif
		};

		// Copy/move constructors.
		//
		variant( const variant& src );
		variant( variant&& vo );

		// Assignment by move/copy both reset current value and redirect to constructor.
		//
		variant& operator=( variant&& vo ) { reset(); return *new ( this ) variant( std::move( vo ) ); }
		variant& operator=( const variant& o ) { reset(); return *new ( this ) variant( o ); }

		// Variant does not have a value if the copy field is null.
		//
		bool has_value() const { return copy_fn != nullptr; }
		operator bool() const { return has_value(); }

		// Gets the address of the object with the given properties.
		// - Will throw assert failure if the variant is empty.
		//
		uint64_t get_address( size_t size, size_t align ) const;

		// Allocates the space for an object of the given properties and returns the pointer.
		//
		void* allocate( size_t size, size_t align );

		// Simple wrappers around get_address.
		// - Will throw assert failure if the variant is empty.
		//
		template<typename T>
		T& get() 
		{ 
			// If safe mode, validate type name (We can compare pointers as it's a unique pointer in .rdata)
			//
#if VTIL_VARIANT_SAFE
			fassert( __typeid_name == typeid( T ).name() );
#endif
			// Calculate the address and return a reference.
			//
			return *( T* ) get_address( sizeof( T ), alignof( T ) ); 
		}
		template<typename T>
		const T& get() const 
		{
			// If safe mode, validate type name (We can compare pointers as it's a unique pointer in .rdata)
			//
#if VTIL_VARIANT_SAFE
			fassert( __typeid_name == typeid( T ).name() );
#endif
			// Calculate the address and return a const qualified reference.
			//
			return *( const T* ) get_address( sizeof( T ), alignof( T ) ); 
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