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

// Furthermore, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information                   |
// |-------------------------|------------------------------------------------|
// | arm64/*                 | https://github.com/aquynh/capstone/            |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#include "arm64_assembler.hpp"
#include <stdexcept>

namespace vtil::arm64
{
	ks_struct* get_ks_handle()
	{
		// Keystone engine is not created until the first call.
		//
		static ks_engine* handle = [ ] ()
		{
			ks_engine* handle;
			if ( ks_open( KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &handle ) != KS_ERR_OK )
				throw std::runtime_error( "Failed to create the Keystone engine!" );
			return handle;
		}( );
		return handle;
	}

	std::vector<uint8_t> assemble( const std::string& src, uint64_t va )
	{
		// Assemble the given instruction in text format.
		//
		size_t size;
		size_t count;
		unsigned char* encode = nullptr;
		if ( ks_asm( get_ks_handle(), src.data(), va, &encode, &size, &count ) )
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