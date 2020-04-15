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
				// Extract first parameter.
				//
				using first_param_t = typename param_pack_first<params...>::type;

				// Invoke if not equal to the reference type.
				//
				return !std::is_same_v<std::remove_cvref_t<first_param_t>, T>;
			}
		}

		template<typename T, typename... params>
		using enable_if_constructor = typename std::enable_if_t<should_invoke_constructor<T, params...>()>;
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
		inline shared_reference() : reference( nullptr ) {}
		inline shared_reference( std::nullptr_t ) : reference( nullptr ) {}

		// Owning reference constructor.
		//
		template<typename... params, typename = impl::enable_if_constructor<shared_reference<T>, params...>>
		inline shared_reference( params&&... p ) : reference( std::make_shared<T>( std::forward<params>( p )... ) ), is_owning( true ) {}

		// Copy-on-write reference construction and assignment.
		//
		inline shared_reference( const shared_reference& ref ) : reference( ref.reference ), is_locked( ref.is_locked ) {}
		inline shared_reference& operator=( const shared_reference& o ) { reference = o.reference; is_locked = o.is_locked; is_owning = false; return *this; }

		// Construction and assignment operator for rvalue references.
		//
		inline shared_reference( shared_reference&& ref ) = default;
		inline shared_reference& operator=( shared_reference&& o ) = default;

		// Simple validity checks.
		//
		inline bool is_valid() const { return ( bool ) reference; }
		inline operator bool() const { return is_valid(); }

		// Locks the current reference, a locked reference cannot be upgraded
		// to a copy-on-write reference as is.
		//
		inline shared_reference& lock() { is_locked = true; is_owning = false; return *this; }

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
		inline bool operator==( const shared_reference& o ) const { return reference == o.reference; }
		inline bool operator<( const shared_reference& o ) const { return reference < o.reference; }

		// Redirect pointer and dereferencing operator to the reference and cast to const-qualified equivalent.
		//
		inline const T* operator->() const { fassert( is_valid() ); return reference.operator->(); }
		inline const T& operator*() const { fassert( is_valid() ); return *reference; }

		// Syntax sugar for ::own() using add operator.
		//
		inline T* operator+() { return own(); }
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