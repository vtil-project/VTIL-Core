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
#include <memory>
#include "type_helpers.hpp"

namespace vtil
{
	namespace impl
	{
		// Virtual type traits.
		//
		template<typename T>
		struct vtype_traits
		{
			// Type information.
			//
			size_t size = sizeof( T );
			size_t alignment = alignof( T );

			// Construction traits.
			//
			bool constructable =                   std::is_constructible_v<T>;
			bool default_constructable =           std::is_default_constructible_v<T>;
			bool trivially_constructable =         std::is_trivially_constructible_v<T>;
			bool trivially_default_constructable = std::is_trivially_default_constructible_v<T>;

			// Copy and move traits.
			//
			bool copy_constructable =              std::is_copy_constructible_v<T>;
			bool move_constructable =              std::is_move_constructible_v<T>;
			bool trivially_copy_constructable =    std::is_trivially_copy_constructible_v<T>;
			bool trivially_move_constructable =    std::is_trivially_move_constructible_v<T>;
		
			bool copy_assignable =                 std::is_copy_constructible_v<T>;
			bool move_assignable =                 std::is_move_constructible_v<T>;
			bool trivially_copy_assignable =       std::is_trivially_copy_constructible_v<T>;
			bool trivially_move_assignable =       std::is_trivially_move_constructible_v<T>;

			// Destruction traits.
			//
			bool destructible =                    std::is_destructible_v<T>;
			bool trivially_destructible =          std::is_trivially_destructible_v<T>;

			// Virtual functions.
			//
			virtual void move_construct( void* self, void* other ) const
			{
				if constexpr ( std::is_move_constructible_v<T> )
					new ( self ) T( std::move( *( T* ) other ) );
				else
					copy_construct( self, other );
			}
			virtual void copy_construct( void* self, const void* other ) const
			{
				if constexpr ( std::is_copy_constructible_v<T> )
					new ( self ) T( *( const T* ) other );
				else
					unreachable();
			}
			virtual void move_assign( void* self, void* other ) const
			{
				if constexpr ( std::is_move_assignable_v<T> )
					*( T* ) self = std::move( *( T* ) other );
				else if constexpr ( std::is_destructible_v<T> && std::is_move_constructible_v<T> )
					std::destroy_at( ( T* ) self ), new ( self ) T( std::move( *( T* ) other ) );
				else
					copy_assign( self, other );
			}
			virtual void copy_assign( void* self, const void* other ) const
			{
				if constexpr ( std::is_copy_assignable_v<T> )
					*( T* ) self = *( const T* ) other;
				else if constexpr ( std::is_destructible_v<T> && std::is_copy_constructible_v<T> )
					std::destroy_at( ( T* ) self ), new ( self ) T( *( const T* ) other );
				else
					unreachable();
			}
			virtual void destruct( void* self ) const
			{
				if constexpr ( std::is_destructible_v<T> )
					std::destroy_at( ( T* ) self );
				else
					unreachable();
			}
			virtual void default_construct( void* self ) const
			{
				if constexpr ( std::is_default_constructible_v<T> )
					new ( self ) T();
				else
					unreachable();
			}
		};
	};
	using vtype_traits_t = impl::vtype_traits<void>;

	template<typename T>
	inline const auto vtype_traits_v = ( const vtype_traits_t* ) &make_default<impl::vtype_traits<T>>();
};