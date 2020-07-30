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
	// Calculates the address of an inline object within the region [begin-end]
	// with the given size and alignment properties.
	//
	template<bool get>
	static uint64_t calc_inline_address( const void* begin, const void* end, size_t size, size_t align )
	{
		// Calculate inline boundaries. 
		//
		uint64_t ptr = ( uint64_t ) begin;
		uint64_t ptr_lim = ( uint64_t ) end;

		// Align as required.
		//
		uint64_t align_mask = align - 1;
		uint64_t ptr_a = ( ptr + align_mask ) & ~align_mask;

		// Skip overflow check if getter.
		//
		if constexpr ( get ) return ptr_a;

		// If overflows, return null, else return the aligned address.
		//
		return ( ptr_a + size ) <= ptr_lim ? ptr_a : 0;
	}
	
	// Copy constructor.
	//
	variant::variant( const variant& src )
	{
		// If source is storing a value:
		//
		if ( src.has_value() )
		{
			// Inherit the copy/destruction traits from source.
			//
			is_trivial_copy = src.is_trivial_copy;
			copy_fn = src.copy_fn;
			destroy_fn = src.destroy_fn;

			// If source is trivially copyable, invoke memcpy.
			//
			if ( src.is_trivial_copy )
				memcpy( allocate( copy_size, copy_align ), ( const void* ) src.get_address( copy_size, copy_align ), copy_size );

			// Otherwise invoke the  copy constructor
			//
			else
				copy_fn( src, *this );

			// If safe, inherit type name.
			//
#if VTIL_VARIANT_SAFE
			__typeid_name = src.__typeid_name;
#endif
		}
		// If source is null, set to null and skip copying.
		//
		else
		{
			copy_fn = nullptr;
		}
	}
	// Move constructor.
	//
	variant::variant( variant&& src )
	{
		// If source has no value, simply create a null variant.
		//
		if ( !src.has_value() )
		{
			copy_fn = nullptr;
			return;
		}

		// If target stores inline value:
		//
		if ( src.is_inline )
		{
			// If type is trivially copyable:
			//
			if ( src.is_trivial_copy )
			{
				// Copy the stored inline value by bytes.
				//
				memcpy( allocate( src.copy_size, src.copy_align ), ( const void* ) src.get_address( src.copy_size, src.copy_align ), src.copy_size );
			}
			// If type is not trivially copyable:
			//
			else
			{
				// Redirect to the copy constructor.
				//
				new ( this ) variant( ( const variant& ) src );

				// Free the object stored in source.
				//
				src.reset();
				return;
			}
		}
		// If target stores an external pointer:
		//
		else
		{
			// Steal the stored external pointer.
			//
			is_inline = false;
			ext = src.ext;
		}

		// Inherit the inline/copy/destruction traits from source.
		//
		is_trivial_copy = src.is_trivial_copy;
		copy_fn = src.copy_fn;
		destroy_fn = src.destroy_fn;

		// If safe, inherit type name.
		//
#if VTIL_VARIANT_SAFE
		__typeid_name = src.__typeid_name;
#endif

		// Mark the source object as freed.
		//
		src.copy_fn = nullptr;
	}
	// Gets the address of the object with the given properties.
	// - Will throw assert failure if the variant is empty.
	//
	uint64_t variant::get_address( size_t size, size_t align ) const
	{
		fassert( has_value() );

		// If object is inline, calculate the inline address, otherwise return the external pointer.
		//
		return is_inline ? calc_inline_address<true>( inl, std::end( inl ), size, align ) : ( uint64_t ) ext;
	}

	// Allocates the space for an object of the given properties and returns the pointer.
	//
	void* variant::allocate( size_t size, size_t align )
	{
		// Calculate the inline address, if successful reference the inline object.
		//
		if ( uint64_t inline_adr = calc_inline_address<false>( inl, std::end( inl ), size, align ) )
		{
			is_inline = true;
			return ( void* ) inline_adr;
		}
		// Invoke aligned malloc.
		//
		else
		{
			is_inline = false;
#ifdef _WIN64
			return ext = _aligned_malloc( size, align );
#else
			return ext = aligned_alloc( align, size );
#endif
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
			// If there is a destructor callback, invoke it.
			//
			if ( destroy_fn ) destroy_fn( *this );

			// If object was not inlined, invoke aligned free.
			//
			if ( !is_inline )
			{
#ifdef _WIN64
				_aligned_free( ext );
#else
				free( ext );
#endif
			}

			// Null copy function to indicate null value.
			//
			copy_fn = nullptr;
		}
	}
};
