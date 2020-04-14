#if _WIN64
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <Windows.h>
#else
    #include <sys/mman.h>
#endif
#include "..\io\asserts.hpp"
#include "rwx_allocator.hpp"

namespace vtil
{
	// If on Windows platform, create a RWX heap.
	//
#if _WIN64
	static HANDLE rwx_heap = HeapCreate( HEAP_CREATE_ENABLE_EXECUTE, 0, 0 );
#endif

	//
	//
	static constexpr uint32_t rwx_mem_magic = 0x1337DEAD;
	struct rwx_mem_desc
	{
		uint32_t magic;
		size_t allocation_size;
	};

	// Allocates <size> bytes of read/write/execute memory.
	//
	void* allocate_rwx( size_t size )
	{
		size += sizeof( rwx_mem_desc );

#if _WIN64
		// Allocate a block of RWX memory from the heap we've created.
		//
		void* p = HeapAlloc( rwx_heap, HEAP_ZERO_MEMORY, size );
#else
		// Allocate new RWX page(s).
		//
		void* p = mmap( 0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
#endif
		// If the API returned NULL, throw exception.
		//
		if ( !p ) throw std::bad_alloc();

		// Cast the type to rwx_mem_desc, write the size and magic.
		//
		rwx_mem_desc* desc = ( rwx_mem_desc* ) p;
		desc->allocation_size = size;
		desc->magic = rwx_mem_magic;

		// Return the data pointer, which is right after the descriptor.
		//
		return desc + 1;
	}

	// Frees the read/write/execute memory at <pointer>.
	//
	void free_rwx( void* pointer ) noexcept
	{
		// Resolve the descriptor which is right before the data, assert magic is valid.
		//
		rwx_mem_desc* desc= ( rwx_mem_desc* ) pointer - 1;
		fassert( desc->magic == rwx_mem_magic );

#if _WIN64
		// Free the heap memory we've allocated.
		//
		HeapFree( rwx_heap, 0, desc );
#else
		// Free the page(s) we've allocated.
		//
		mmunmap( desc, desc->allocation_size );
#endif
	}
};