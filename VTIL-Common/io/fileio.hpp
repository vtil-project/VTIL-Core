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

// Declare a simple interface to read/write files for convenience.
//
namespace vtil::file
{
	// Binary I/O.
	//
	template<Trivial T = uint8_t>
	static std::vector<T> read_raw( const std::filesystem::path& path )
	{
		// Try to open file as binary for read.
		//
		std::ifstream file( path, std::ios::binary );
		if ( !file.good() ) logger::error( "File %s cannot be opened for read.", path );

		// Determine file length and validity.
		//
		file.seekg( 0, std::ios_base::end );
		std::streampos length = file.tellg();
		file.seekg( 0, std::ios_base::beg );
		fassert( ( length % sizeof( T ) ) == 0 );

		// Read the whole file and return.
		//
		std::vector<T> buffer( length / sizeof( T ) );
		file.read( (char*) buffer.data(), length );
		return buffer;
	}

	static void write_raw( const std::filesystem::path& path, void* data, size_t size )
	{
		// Try to open file as binary for write.
		//
		std::ofstream file( path, std::ios::binary );
		if ( !file.good() ) logger::error( "File %s cannot be opened for write.", path );

		// Write the data and return.
		//
		file.write( ( char* ) data, size );
	}

	template<Iterable C = std::initializer_list<uint8_t>> requires ( Trivial<iterator_value_type_t<C>> )
	static void write_raw( const std::filesystem::path& path, C&& container )
	{
		// Try to open file as binary for write.
		//
		std::ofstream file( path, std::ios::binary );
		if ( !file.good() ) logger::error( "File %s cannot be opened for write.", path );

		// Write every element and return.
		//
		if constexpr ( !is_linear_iterable_v<C> )
		{
			for ( auto& e : container )
				file.write( ( char* ) e, sizeof( iterator_value_type_t<C> ) );
		}
		else
		{
			file.write( ( char* ) &*std::begin( container ), std::size( container ) * sizeof( iterator_value_type_t<C> ) );
		}
	}

	// String I/O.
	//
	template<typename C = char>
	static std::vector<std::basic_string<C>> read_lines( const std::filesystem::path& path )
	{
		// Try to open file as string for read.
		//
		std::basic_ifstream<C> file( path );
		if ( !file.good() ) logger::error( "File %s cannot be opened for read.", path );

		// Read every lines and return.
		//
		std::vector<std::basic_string<C>> output;
		while ( std::getline( file, output.emplace_back() ) );
		output.pop_back();
		return output;
	}

	template<typename C = char>
	static std::basic_string<C> read_string( const std::filesystem::path& path )
	{
		// Try to open file as string for read.
		//
		std::basic_ifstream<C> file( path );
		if ( !file.good() ) logger::error( "File %s cannot be opened for read.", path );

		// Read the whole file and return.
		//
		return { std::istreambuf_iterator<C>( file ), {} };
	}

	template<Iterable C = std::initializer_list<std::string_view>> requires( String<iterator_value_type_t<C>> )
	static void write_lines( const std::filesystem::path& path, C&& container )
	{
		using char_type = string_unit_t<iterator_value_type_t<C>>;

		// Try to open file as string for write.
		//
		std::basic_ofstream<char_type> file( path );
		if ( !file.good() ) logger::error( "File %s cannot be opened for write.", path );

		// Write every line and return.
		//
		for ( std::basic_string_view<char_type> view : container )
		{
			file.write( view.data(), view.size() );
			file << std::endl;
		}
	}

	template<String S = std::string_view>
	static void write_string( const std::filesystem::path& path, S&& data )
	{
		using char_type = string_unit_t<S>;

		// Try to open file as string for write.
		//
		std::basic_ofstream<char_type> file( path );
		if ( !file.good() ) logger::error( "File %s cannot be opened for write.", path );

		// Write the whole string and return.
		//
		std::basic_string_view<char_type> view = data;
		file.write( view.begin(), view.size() );
	}
};