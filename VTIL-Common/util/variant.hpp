#pragma once
#include <type_traits>
#include <functional>
#include <stdint.h>
#include <optional>
#include "..\io\asserts.hpp"

#ifdef _DEBUG
	#if __has_feature(cxx_rtti) || defined(__GXX_RTTI) || defined(_CPPRTTI)
		#define VTIL_SAFE_VARIANT
	#endif
#endif

namespace vtil
{
	// Variant can be used to store values of any type in a fast way.
	//
	struct variant
	{
		static constexpr size_t small_type_optimization_limit = 0x30;

		// Value is either stored in the [char inl[]] as an inline object,
		// or in [void* ext] as an external pointer.
		//
		union
		{
			char inl[ small_type_optimization_limit ];
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
				size_t copy_size : 32;
				size_t copy_align : 32;
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

		// Constructs variant from any type.
		//
		template<typename T, std::enable_if_t<!std::is_same_v<T, variant>, int> = 0>
		variant( const T& value )
		{
			// Invoke copy constructor on allocated space.
			//
			T* out = new ( allocate( sizeof( T ), alignof( T ) ) ) T( value );

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
#ifdef VTIL_SAFE_VARIANT
			__typeid_name = typeid( T ).name();
#endif
		};

		// Copy/move constructors.
		//
		variant( const variant& src );
		variant( variant&& vo );

		// Assignment by move/copy both reset current value and redirect to constructor.
		//
		inline variant& operator=( variant&& vo ) { reset(); return *new ( this ) variant( std::move( vo ) ); }
		inline variant& operator=( const variant& o ) { reset(); return *new ( this ) variant( o ); }

		// Variant does not have a value if the copy field is null.
		//
		inline bool has_value() const { return copy_fn != nullptr; }
		inline operator bool() const { return has_value(); }

		// Gets the address of the object with the given properties.
		// - Will throw assert failure if the variant is empty.
		//
		size_t get_address( size_t size, size_t align ) const;

		// Allocates the space for an object of the given properties and returns the pointer.
		//
		void* allocate( size_t size, size_t align );

		// Simple wrappers around get_address.
		// - Will throw assert failure if the variant is empty.
		//
		template<typename T>
		inline T& get() 
		{ 
			// If safe mode, validate type name (We can compare pointers as it's a unique pointer in .rdata)
			//
#ifdef VTIL_SAFE_VARIANT
			fassert( __typeid_name == typeid( T ).name() );
#endif
			// Calculate the address and return a reference.
			//
			return *( T* ) get_address( sizeof( T ), alignof( T ) ); 
		}
		template<typename T>
		inline const T& get() const 
		{
			// If safe mode, validate type name (We can compare pointers as it's a unique pointer in .rdata)
			//
#ifdef VTIL_SAFE_VARIANT
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
		inline std::optional<T> as() const { return has_value() ? std::optional{ get<T>() } : std::nullopt; }

		// Deletes the currently stored variant.
		//
		void reset();
		inline ~variant() { reset(); }
	};
};