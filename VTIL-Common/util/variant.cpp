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
#include "variant.hpp"
#include <stdlib.h>

namespace vtil
{
	// Copy constructor.
	//
	variant::variant( const variant& src )
	{
		// If source is storing a value:
		//
		if ( src.has_value() )
		{
			// Inherit the type traits from source.
			//
			traits = src.traits;

			// Invoke copy construction.
			//
			traits->copy_construct( allocate( traits->size ), src.get_address() );
		}
		// If source is null, set null.
		//
		else
		{
			traits = nullptr;
		}
	}

	// Move constructor.
	//
	variant::variant( variant&& src )
	{
		// If source is storing a value:
		//
		if ( src.has_value() )
		{
			// Inherit the type traits from source.
			//
			traits = src.traits;

			// If target stores an external pointer:
			//
			if( !src.is_inline )
			{
				// Steal the stored external pointer.
				//
				is_inline = false;
				ext = src.ext;

				// Mark the source object as null.
				//
				src.traits = nullptr;
			}
			else
			{
				// Invoke move construction.
				//
				traits->move_construct( allocate( traits->size ), src.get_address() );
			}
		}
		// If source is null, set null.
		//
		else
		{
			traits = nullptr;
		}
	}

	// Move assignment.
	//
	variant& variant::operator=( variant&& vo )
	{ 
		// If target is null, reset self.
		//
		if ( !vo.has_value() )
		{
			reset();
			return *this;
		}

		// If target stores an external pointer or null:
		//
		if ( !vo.is_inline )
		{
			// Swap with current and return.
			//
			std::swap( as_bytes( *this ), as_bytes( vo ) );
			return *this;
		}

		// If same type, invoke assignment.
		//
		if ( traits == vo.traits )
		{
			traits->move_assign( get_address(), vo.get_address() );
			return *this;
		}

		// Otherwise, reset and construct again.
		//
		reset(); 
		return *new ( this ) variant( std::move( vo ) ); 
	}

	// Copy assignment.
	//
	variant& variant::operator=( const variant& o )
	{ 
		// If target is null, reset self.
		//
		if ( !o.has_value() )
		{
			reset();
			return *this;
		}

		// If same type, invoke assignment.
		//
		if ( traits == o.traits )
		{
			traits->copy_assign( get_address(), o.get_address() );
			return *this;
		}

		// Otherwise, reset and construct again.
		//
		reset();
		return *new ( this ) variant( o );
	}

	// Allocates the space for an object of the given properties and returns the pointer.
	//
	void* variant::allocate( size_t size )
	{
		// Calculate the inline address, if successful reference the inline object.
		//
		if ( size <= VTIL_VARIANT_INLINE_LIMIT )
		{
			is_inline = true;
			return ( void* ) &inl[ 0 ];
		}
		// Invoke malloc.
		//
		else
		{
			is_inline = false;
			return ext = malloc( size );
		}
	}

	// Deletes the currently stored variant.
	//
	void variant::reset()
	{
		// If variant is storing any value:
		//
		if ( has_value() )
		{
			// Invoke destruction.
			//
			traits->destruct( get_address() );

			// If object was not inlined, invoke free.
			//
			if ( !is_inline )
				free( ext );

			// Null traits to indicate null value.
			//
			traits = nullptr;
		}
	}
};
