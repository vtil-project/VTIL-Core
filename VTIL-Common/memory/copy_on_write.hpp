// Copyright (c) 2020 Can Bölük and contributors of the VTIL Project		   
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
// Furthermode, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information				      |
// |-------------------------|------------------------------------------------|
// | amd64/*                 | https://github.com/aquynh/capstone/		      |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
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


		template <typename T, typename... params>
		inline static std::shared_ptr<T> make_shared( params&&... args )
		{ 
			std::shared_ptr<T> out = std::make_shared<T>( std::forward<params>( args )... );

			// Billion dollar company yes?
			//
#ifdef __INTEL_COMPILER
			{
				std::weak_ptr<T> __tmp = out;
				new ( &__tmp ) std::weak_ptr<T>{};
			}
#endif
			return out;
		}
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
		shared_reference() : reference( nullptr ) {}
		shared_reference( std::nullptr_t ) : reference( nullptr ) {}

		// Owning reference constructor.
		//
		template<typename... params, typename = impl::enable_if_constructor<shared_reference<T>, params...>>
		shared_reference( params&&... p ) : reference( impl::make_shared<T>( std::forward<params>( p )... ) ), is_owning( true ) {}

		// Copy-on-write reference construction and assignment.
		//
		shared_reference( const shared_reference& ref ) : reference( ref.reference ), is_locked( ref.is_locked ) {}
		shared_reference& operator=( const shared_reference& o ) { reference = o.reference; is_locked = o.is_locked; is_owning = false; return *this; }

		// Construction and assignment operator for rvalue references.
		//
		shared_reference( shared_reference&& ref ) = default;
		shared_reference& operator=( shared_reference&& o ) = default;

		// Simple validity checks.
		//
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
				reference = impl::make_shared<T>( *reference );
				
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
					reference = impl::make_shared<T>( *reference );

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