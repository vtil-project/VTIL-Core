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
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "../io/logger.hpp"

namespace vtil::file
{
	// Declare a simple interface to read/write files for convenience.
	//
	static std::vector<uint8_t> read_raw( const std::filesystem::path& path )
	{
		// Try to open file as binary for read.
		//
		std::ifstream file( path, std::ios::binary );
		if ( !file.good() ) logger::error( "File %s cannot be opened.", path );

		// Read the whole file and return.
		//
		return std::vector<uint8_t>( std::istreambuf_iterator<char>( file ), {} );
	}

	static void write_raw( const std::filesystem::path& path, void* data, size_t size )
	{
		// Try to open file as binary for write.
		//
		std::ofstream file( path, std::ios::binary );
		if ( !file.good() ) logger::error( "File cannot be opened for write." );

		// Write the data and return.
		//
		file.write( ( char* ) data, size );
	}

	template<Iterable T> requires ( is_linear_iterable_v<T> && std::is_trivial_v<iterated_type_t<T>> )
	static void write_raw( const std::filesystem::path& path, T&& container )
	{
		write_raw( path, &*std::begin( container ), std::size( container ) * sizeof( iterated_type_t<T> ) );
	}
};