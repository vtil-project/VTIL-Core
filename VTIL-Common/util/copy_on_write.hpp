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
#include "../util/intrinsics.hpp"
#include "../util/type_helpers.hpp"

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

	// Used to implement shared and extremely fast Copy-on-Write memory.
	//
	template<typename T>
	struct shared_reference
	{
		// Declare the object entry and its pool.
		//
		using object_entry =   std::pair<T, std::atomic<long>>;
		using object_pool  =   object_pool<object_entry>;

		// Wrap atomic operations on reference counter.
		//
		__forceinline static void inc_ref( object_entry* entry )
		{
#ifdef _MSC_VER
			std::atomic_fetch_add_explicit( &entry->second, +1, std::memory_order::relaxed );
#else
			entry->second++;
#endif
		}
		__forceinline static bool dec_ref( object_entry* entry )
		{
#ifdef _MSC_VER
			return std::atomic_fetch_add_explicit( &entry->second, -1, std::memory_order::acq_rel ) == 1;
#else
			return --entry->second == 0;
#endif
		}
		__forceinline static long get_ref( object_entry* entry )
		{
#ifdef _MSC_VER
			return std::atomic_load_explicit( &entry->second, std::memory_order::relaxed );
#else
			return entry->second.load();
#endif
		}

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

			T* _value;
			object_entry* _entry;
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
			combined_value = ( uint64_t ) object_pool::construct
			(
				/*Object itself*/     T( std::forward<params>( p )... ), 
				/*Reference counter*/ 1
			);
		}

		// Shared reference constructor.
		//
		shared_reference( const shared_reference& ref )
			: combined_value( ref.combined_value )
		{
			// If object is null, return.
			//
			if ( !combined_value )
				return;

			// If object is temporary (flag implies non-null), gain ownership of the reference.
			//
			if ( is_temporary() ) [[unlikely]]
				combined_value = ( uint64_t ) object_pool::construct( *get(), 1 );
			// Otherwise, increment reference.
			//
			else
				inc_ref( get_entry() );
		}
		shared_reference& operator=( const shared_reference& o ) 
		{ 
			// If object is null, reset and return.
			//
			if ( !o.combined_value ) [[unlikely]]
				return reset();

			// If object is temporary (flag implies non-null):
			//
			if ( o.is_temporary() ) [[unlikely]]
			{
				// If we have valid unique memory, copy over it:
				//
				if( combined_value && !is_temporary() && get_ref( get_entry() ) == 1 )
					*_value = *o.get();
				// Otherwise, allocate:
				//
				else
					reset().combined_value = ( uint64_t ) object_pool::construct( *o.get(), 1 );
			}
			// If we hold a valid entry:
			//
			else if ( combined_value && !is_temporary() ) [[likely]]
			{
				// Return as is if same entry.
				//
				object_entry* prev = get_entry();
				if ( prev == o.get_entry() ) [[unlikely]]
					return *this;

				// Copy combined value and increment reference.
				//
				inc_ref( o.get_entry() );
				combined_value = o.combined_value;

				// Decrement previous entry's reference, if reached 0, destruct.
				//
				if ( dec_ref( prev ) )
					object_pool::destruct( prev );
			}
			// Otherwise, copy combined value and increment reference.
			//
			else
			{
				inc_ref( o.get_entry() );
				combined_value = o.combined_value;
			}
			return *this;
		}

		// Construction and assignment operator for rvalue references.
		//
		shared_reference( shared_reference&& ref )
			: combined_value( std::exchange( ref.combined_value, 0 ) ) {}
		shared_reference& operator=( shared_reference&& o )
		{
			uint64_t value = std::exchange( o.combined_value, 0 );
			reset().combined_value = value;
			return *this;
		}

		// Gets object entry.
		//
		constexpr object_entry* get_entry() const { dassert( !is_temporary() ); return _entry; }

		// Gets object itself.
		//
		constexpr const T* get() const { return ( const T* ) pointer; }

		// Check if temporary pointer.
		// - Micro optimized to generate cmp branch instead of bitmasked 
		//   test since MSVC is too stupid apparently.
		//
		constexpr bool is_temporary() const { return ( ( int64_t ) combined_value ) < 0; /*return temporary;*/ }

		// Converts to owning reference.
		//
		T* own()
		{
			// If temporary, copy first.
			//
			if ( is_temporary() ) [[unlikely]]
			{
				combined_value = ( uint64_t ) object_pool::construct( *get(), 1 );
			}
			// If shared, copy if reference count is above 1.
			//
			else if ( get_ref( get_entry() ) != 1 ) [[likely]]
			{
				auto prev = get_entry();
				combined_value = ( uint64_t ) object_pool::construct( *_value, 1 );
				if ( dec_ref( prev ) ) [[unlikely]]
					object_pool::destruct( prev );
			}

			// Return the current pointer without const-qualifiers.
			//
			return ( T* ) combined_value;
		}

		// Simple validity checks.
		//
		constexpr bool is_valid() const { return combined_value; }
		constexpr explicit operator bool() const { return is_valid(); }

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
		constexpr bool operator==( const shared_reference& o ) const { return combined_value == o.combined_value; }
		constexpr bool operator<( const shared_reference& o ) const { return combined_value < o.combined_value; }

		// Redirect pointer and dereferencing operator to the reference and cast to const-qualified equivalent.
		//
		constexpr const T* operator->() const { return get(); }
		constexpr const T& operator*() const { return *get(); }

		// Syntax sugar for ::own() using the + operator.
		// -- If temporary, return as is.
		//
		T* operator+() 
		{ 
			if ( is_temporary() ) [[unlikely]]
				return ( T* ) pointer;
			return own(); 
		}

		// Resets the reference to nullptr.
		//
		__forceinline shared_reference& reset()
		{
			// If non-temporary and non-null, decrement reference count, if 
			// it reaches 0, destroy the object and deallocate.
			//
			if ( combined_value && !is_temporary() && dec_ref( get_entry() ) )
				object_pool::destruct( get_entry() );
			
			// Clear combined value and return.
			//
			combined_value = 0;
			return *this;
		}

		// Constructor invokes reset.
		//
		~shared_reference() { reset(); }
	};

	// Weak references are used to store shared references without implying 
	// ownership. This class should not be used together with temporaries.
	//
	template<typename T>
	struct weak_reference
	{
		union
		{
			struct
			{
				uint64_t pointer : 63;
				uint64_t temporary : 1;
			};
			uint64_t combined_value;
			
			T* _value;
		};

		// Default null constructor.
		//
		constexpr weak_reference() : combined_value( 0 ) {}
		constexpr weak_reference( std::nullptr_t ) : combined_value( 0 ) {}
		
		// Reference borrowing constructor/assignment.
		//
		constexpr weak_reference( const shared_reference<T>& ref )
			: combined_value( ref.combined_value ) {}
		constexpr weak_reference& operator=( const shared_reference<T>& ref ) { return *new ( this ) weak_reference( ref ); }
		
		// Default copy/move behaviour.
		//
		constexpr weak_reference( weak_reference&& ) = default;
		constexpr weak_reference( const weak_reference& ) = default;
		constexpr weak_reference& operator=( weak_reference&& ) = default;
		constexpr weak_reference& operator=( const weak_reference& ) = default;

		// Basic comparison operators are redirected to the pointer type.
		//
		constexpr bool operator<( const weak_reference& o ) const { return combined_value < o.combined_value; }
		constexpr bool operator==( const weak_reference& o ) const { return combined_value == o.combined_value; }
		constexpr bool operator<( const shared_reference<T>& o ) const { return combined_value < o.combined_value; }
		constexpr bool operator==( const shared_reference<T>& o ) const { return combined_value == o.combined_value; }

		// Redirect pointer and dereferencing operator to the reference and cast to const-qualified equivalent.
		//
		constexpr const T* get() const { return ( const T* ) pointer; }
		constexpr const T* operator->() const { return get(); }
		constexpr const T& operator*() const { return *get(); }

		// Simple validity checks.
		//
		constexpr bool is_valid() const { return get(); }
		constexpr explicit operator bool() const { return is_valid(); }
		
		// Convert to shared reference, will cause it to actually reference if decays, huge hack but will work
		// and be really efficient because of the way shared references work.
		//
		const shared_reference<T>& make_shared() const { return *( const shared_reference<T>* ) &combined_value; }
	};

	// Explicit temporary reference creation.
	//
	template<typename T>
	__forceinline static constexpr shared_reference<T> make_local_reference( const T* ptr )
	{
		shared_reference<T> ret;
		ret.pointer = ( uint64_t ) ptr;
		ret.temporary = true;
		return ret;
	}
};