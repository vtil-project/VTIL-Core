#pragma once
#include <memory>
#include <functional>
#include <type_traits>
#include "..\io\asserts.hpp"

// Thanks visual studio.
//
#ifdef __INTELLISENSE__
	#define __builtin_frame_address(level) ((void*)1337)
#endif

// The copy-on-write interface defined here is used to avoid deep duplications of 
// containers such as trees when a VTIL routine is working with them.
//
namespace vtil
{
	namespace impl
	{
		template<typename... params> struct param_pack_first { using type = std::tuple_element_t<0, std::tuple<params...>>; };
		template<> struct param_pack_first<> { using type = void; };

		template<typename T, typename... params>
		using enable_if_non_equ_valid_t = typename std::enable_if_t<!std::is_same_v<std::remove_cvref_t<typename param_pack_first<params...>::type>, T>>;
	};

	// This structure is used to describe copy-on-write references.
	//
	template<typename T>
	struct shared_reference
	{
		// The original reference and current state.
		//
		std::shared_ptr<T> reference;
		bool is_owning = false;
		bool is_locked = false;

		// Null reference construction.
		//
		shared_reference() {}
		shared_reference( std::nullptr_t ) {}

		// Owning reference constructor.
		//
		shared_reference( T&& obj ) : reference( std::make_shared<T>( std::move( obj ) ) ), is_owning( true ) {}
		shared_reference( const T& obj ) : reference( std::make_shared<T>( obj ) ), is_owning( true ) {}
		template<typename... params, typename = impl::enable_if_non_equ_valid_t<shared_reference<T>, params..., shared_reference<T>>>
		shared_reference( params&&... p ) : reference( std::make_shared<T>( std::forward<params>( p )... ) ), is_owning( true ) {}

		// Copy-on-write reference construction and assignment.
		//
		shared_reference( const shared_reference& ref ) : reference( ref.reference ), is_locked( ref.is_locked ) {}
		shared_reference& operator=( const shared_reference& o ) { reference = o.reference; is_locked = o.is_locked; is_owning = false; return *this; }

		// Construction and assignment operator for rvalue references.
		//
		shared_reference( shared_reference&& ref ) : reference( std::move( ref.reference ) ), is_owning( std::move( ref.is_owning ) ), is_locked( std::move( ref.is_locked ) ) {}
		shared_reference& operator=( shared_reference&& o ) { reference = std::move( o.reference ); is_owning = std::move( o.is_owning ); is_locked = std::move( o.is_locked ); return *this; }

		// Simple validity checks.

		bool is_valid() const { return ( bool ) reference; }
		operator bool() const { return is_valid(); }

		// Locks the current reference, a locked reference cannot be upgraded
		// to a copy-on-write reference as is.
		//
		shared_reference& lock() { is_locked = true; is_owning = false; return *this; }

		// Unlocks the current reference, should be called before storing the reference.
		//
		shared_reference& unlock()
		{ 
			// If reference is locked, we need to copy it.
			//
			if ( is_locked )
			{
				// Create a copy and change reference to point at it.
				//
				reference = std::make_shared<T>( *reference );
				
				// Mark as unlocked and owning.
				//
				is_locked = true;
				is_owning = true;
			}
			return *this; 
		}

		// Converts this reference to an owning one if it is not one already and 
		// returns the pointer to the base type with no const-qualifiers.
		//
		T* own()
		{
			fassert( is_valid() );

			// If copy-on-write, convert to owning first.
			//
			if ( !is_owning )
			{
				// If use counter is above 1 or reference is locked, we need 
				// to make a copy before modifying the reference.
				//
				if ( reference.use_count() > 1 || is_locked )
					reference = std::make_shared<T>( *reference );

				// Mark as unlocked and owning.
				//
				is_owning = true;
				is_locked = false;
			}

			// Redirect the operator to the reference.
			//
			return reference.operator->();
		}

		// Basic comparison operators are redirected to the pointer type.
		//
		bool operator==( const shared_reference& o ) const { return reference == o.reference; }
		bool operator<( const shared_reference& o ) const { return reference < o.reference; }

		// Redirect pointer and dereferencing operator to the reference and cast to const-qualified equivalent.
		//
		const T* operator->() const { fassert( is_valid() ); return reference.operator->(); }
		const T& operator*() const { fassert( is_valid() ); return *reference; }

		// Syntax sugar for ::own() using add operator.
		//
		T* operator+() { return own(); }
	};

	// Local references are used to create copy-on-write references to values on stack, 
	// note that they should not be stored under any condition.
	//
	template<typename T>
	__forceinline shared_reference<T> make_local_reference( T* variable_pointer )
	{
		// Save current frame address.
		//
		void* creation_frame = __builtin_frame_address( 0 );

		// Create a shared_reference from a custom std::shared_ptr.
		//
		shared_reference<T> output;
		output.reference = std::shared_ptr<T>{ variable_pointer, [ creation_frame ] ( T* ptr )
		{
			// Should not be destructed above current frame.
			//
			fassert( creation_frame > __builtin_frame_address( 0 ) );
		} };

		// Mark as locked and return.
		//
		output.is_locked = true;
		return output;
	}
};