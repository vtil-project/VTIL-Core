#include "assembler.hpp"
#include <keystone/keystone.h>
#pragma comment(lib, "keystone.lib")

namespace keystone
{
	ks_struct* get_handle()
	{
		// Keystone engine is not created until the first call.
		//
		static ks_engine* handle = [ ] ()
		{
			ks_engine* handle;
			if ( !ks_open( KS_ARCH_X86, KS_MODE_64, &handle ) )
				throw std::exception( "Failed to create the Capstone engine!" );
			return handle;
		}( );
		return handle;
	}

	std::vector<uint8_t> assemble( const std::string& src, uint64_t va )
	{
		// Assemble the given instruction in text format.
		// - (Not too sure why I have to do the .code64; hack, but won't question.)
		//
		size_t size;
		size_t count;
		unsigned char* encode = nullptr;
		if ( ks_asm( get_handle(), ( ".code64;" + src ).data(), va, &encode, &size, &count ) )
		{
			// Free (if relevant) and return on failure.
			//
			if ( encode ) ks_free( encode );
			return {};
		}

		// Convert to a vector of bytes, free the encoding and return it.
		//
		std::vector<uint8_t> output = { encode, encode + size };
		ks_free( encode );
		return output;
	}
};