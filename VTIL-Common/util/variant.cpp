#include "variant.hpp"

namespace vtil
{
	// Calculates the address of an inline object within the region [begin-end]
	// with the given size and alignment properties.
	//
	static size_t calc_inline_address( const void* begin, const void* end, size_t size, size_t align )
	{
		// Calculate inline boundaries. 
		//
		size_t ptr = ( size_t ) begin;
		size_t ptr_lim = ( size_t ) end;

		// Align as required.
		//
		size_t align_mask = align - 1;
		size_t ptr_a = ( ptr + align_mask ) & ~align_mask;

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
		if ( !src.has_value() )
		{
			// If source is trivially copyable, invoke memcpy.
			//
			if ( src.is_trivial_copy )
				memcpy( allocate( copy_size, copy_align ), ( const void* ) src.get_address( copy_size, copy_align ), copy_size );

			// Otherwise invoke the  copy constructor
			//
			else
				src.copy_fn( src, *this );

			// Inherit the copy/destruction traits from source.
			//
			is_trivial_copy = src.is_trivial_copy;
			copy_fn = src.copy_fn;
			destroy_fn = src.destroy_fn;

			// If debug mode, inherit type name.
			//
#ifdef _DEBUG
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
				new ( this ) variant( ( variant& ) src );

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
			ext = std::move( src.ext );
		}

		// Inherit the inline/copy/destruction traits from source.
		//
		is_trivial_copy = src.is_trivial_copy;
		copy_fn = src.copy_fn;
		destroy_fn = src.destroy_fn;

		// If debug mode, inherit type name.
		//
#ifdef _DEBUG
		__typeid_name = src.__typeid_name;
#endif

		// Mark the source object as freed.
		//
		src.copy_fn = nullptr;
	}
	// Gets the address of the object with the given properties.
	// - Will throw assert failure if the variant is empty.
	//
	size_t variant::get_address( size_t size, size_t align ) const
	{
		fassert( has_value() );

		// If object is inline, calculate the inline address, otherwise return the external pointer.
		//
		return is_inline ? calc_inline_address( inl, std::end( inl ), size, align ) : ( size_t ) ext;
	}

	// Allocates the space for an object of the given properties and returns the pointer.
	//
	void* variant::allocate( size_t size, size_t align )
	{
		// Calculate the inline address, if successful reference the inline object.
		//
		if ( size_t inline_adr = calc_inline_address( inl, std::end( inl ), size, align ) )
		{
			is_inline = true;
			return ( void* ) inline_adr;
		}
		// Invoke aligned malloc.
		//
		else
		{
			is_inline = false;
			return ext = _aligned_malloc( size, align );
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
			if ( !is_inline ) _aligned_free( ext );

			// Null copy function to indicate null value.
			//
			copy_fn = nullptr;
		}
	}
};
