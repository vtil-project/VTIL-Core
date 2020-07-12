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
#include <memory>
#include <functional>
#include <type_traits>
#include <atomic>
#include "../io/asserts.hpp"
#include "object_pool.hpp"

// Define _AddressOfReturnAddress() for compilers that do not have it. 
// 
#if not defined(_MSC_VER) and not defined(__INTELLISENSE__) 
	#define __forceinline __attribute__((always_inline)) 
	#define _AddressOfReturnAddress() __builtin_frame_address(0) 
#endif 

// The copy-on-write interface defined here is used to avoid deep duplications of 
// containers such as trees when a VTIL routine is working with them.
//
namespace vtil
{
	namespace impl
	{
		template<typename... params> struct first_of { using type = std::tuple_element_t<0, std::tuple<params...>>; };
		template<> struct first_of<> { using type = void; };

		template<typename... params>
		using first_of_t = typename first_of<params...>::type;

		template<typename T, typename... params>
		static constexpr bool should_invoke_constructor()
		{
			// Constructor should be always invoked if we have more than one parameter and 
			// never if we have zero parameters.
			//
			if constexpr ( sizeof...( params ) != 1 )
			{
				return sizeof...( params ) != 0;
			}
			else
			{
				// Invoke if not equal to the reference type.
				//
				return !std::is_base_of_v<T, std::remove_cvref_t<first_of_t<params...>>>;
			}
		}

		template<typename T, typename... params>
		using enable_if_constructor = typename std::enable_if_t<should_invoke_constructor<T, params...>(), int>;

		template<typename T>
		inline static T* reloc_const( const T* ptr, const void* src, void* dst )
		{
			int64_t reloc_delta = ( int64_t ) dst - ( int64_t ) src;
			return ( T* ) ( ( uint64_t ) ptr + reloc_delta );
		}

		template<typename T>
		inline static T& reloc_const( const T& ref, const void* src, void* dst )
		{
			int64_t reloc_delta = ( int64_t ) dst - ( int64_t ) src;
			return *( T* ) ( ( uint64_t ) &ref + reloc_delta );
		}
	};

	template<typename T>
	struct shared_reference
	{
		// Declare the allocator.
		//
		using object_entry = std::pair<T, std::atomic<size_t>>;
		using allocator =    object_pool<object_entry>;

		// Store pointer as a 63-bit integer and append an additional bit to control temporary/allocated.
		//
		union
		{
			struct
			{
				uint64_t pointer   : 63;
				uint64_t temporary : 1;
			};
			uint64_t combined_value;
		};

		// Null reference construction.
		//
		constexpr shared_reference() : combined_value( 0 ) {}
		constexpr shared_reference( std::nullptr_t ) : shared_reference() {}
		constexpr shared_reference( std::nullopt_t ) : shared_reference() {}

		// Owning reference constructor.
		//
		template<typename... params, impl::enable_if_constructor<shared_reference<T>, params...> = 0>
		shared_reference( params&&... p ) 
		{
			object_entry* entry = allocator{}.allocate();
			new ( &entry->first ) T( std::forward<params>( p )... );
			entry->second = { 1 };

			pointer = ( uint64_t ) entry;
			temporary = false;
		}

		// Shared reference constructor.
		//
		shared_reference( const shared_reference& ref )
			: combined_value( ref.combined_value )
		{
			// If object is temporary (flag implies non-null),
			// gain ownership of the reference.
			//
			if ( temporary )
				own();
			// If object is (non-null) and shared, increment reference.
			//
			else if ( auto entry = get_entry() ) 
				entry->second++;
		}
		shared_reference& operator=( const shared_reference& o ) 
		{ 
			shared_reference copy = o; // This fixes cases where o was referenced by self and it gets deallocated.
			return *new ( &reset() ) shared_reference( std::move( copy ) );
		}

		// Construction and assignment operator for rvalue references.
		//
		shared_reference( shared_reference&& ref )
			: combined_value( std::exchange( ref.combined_value, 0 ) ) {}
		shared_reference& operator=( shared_reference&& o )
		{
			reset().combined_value = std::exchange( o.combined_value, 0 );
			return *this;
		}

		// Gets object entry.
		//
		object_entry* get_entry() const { dassert( !temporary ); return ( object_entry* ) pointer; }

		// Gets object itself.
		//
		const T* get() const { return ( const T* ) pointer; }

		// Converts to owning reference.
		//
		T* own()
		{
			// If temporary, copy first.
			//
			if ( temporary )
			{
				object_entry* new_entry = allocator{}.allocate();
				new ( &new_entry->first ) T{ *get() };
				new_entry->second = { 1 };

				pointer = ( uint64_t ) new_entry;
				temporary = false;
			}
			// If shared, copy if reference count is above 1.
			//
			else if ( auto entry = get_entry(); entry && entry->second != 1 )
			{
				object_entry* new_entry = allocator{}.allocate();
				new ( &new_entry->first ) T{ *get() };
				new_entry->second = { 1 };
				entry->second--;

				pointer = ( uint64_t ) new_entry;
				temporary = false;
			}

			// Return the current pointer without const-qualifiers.
			//
			return ( T* ) pointer;
		}

		// Simple validity checks.
		//
		bool is_valid() const { return get(); }
		explicit operator bool() const { return is_valid(); }

		// Wrapper around ::own that can be called with arguments that are const-qualified 
		// pointers or references which we will relocate to the new object as non-const qualified 
		// owned instances of them.
		//
		template<typename... X>
		auto own( X... params )
		{
			const T* prev = get();
			T* owned = own();
			return reference_as_tuple( ( T* ) owned, impl::reloc_const( std::forward<X>( params ), prev, owned )... );
		}

		// Basic comparison operators are redirected to the pointer type.
		//
		bool operator==( const shared_reference& o ) const { return combined_value == o.combined_value; }
		bool operator<( const shared_reference& o ) const { return combined_value < o.combined_value; }

		// Redirect pointer and dereferencing operator to the reference and cast to const-qualified equivalent.
		//
		const T* operator->() const { return get(); }
		const T& operator*() const { return *get(); }

		// Syntax sugar for ::own() using the + operator.
		// -- If temporary, return as is.
		//
		T* operator+() { return temporary ? ( T* ) pointer : own(); }

		// Resets the reference to nullptr.
		//
		shared_reference& reset()
		{
			// If non-temporary and non-null, decrement reference count, if 
			// it reaches 0, destroy the object and deallocate.
			//
			if ( !temporary )
			{
				if ( auto entry = get_entry() )
				{
					if ( --entry->second == 0 )
					{
						( ( T* ) &entry->first )->~T();
						allocator{}.deallocate( ( object_entry* ) entry );
					}
				}
			}
			
			// Clear combined value and return.
			//
			combined_value = 0;
			return *this;
		}

		// Constructor invokes reset.
		//
		~shared_reference() { reset(); }
	};

	// Explicit temporary reference creation.
	//
	template<typename T>
	__forceinline static shared_reference<T> make_local_reference( const T* ptr )
	{
		shared_reference<T> ret;
		ret.pointer = ( uint64_t ) ptr;
		ret.temporary = true;
		return ret;
	}
};
