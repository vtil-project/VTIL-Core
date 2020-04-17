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
#pragma once
#include <string>
#include <type_traits>

#define FMT_TEMP_REG	"t%d"
#define FMT_INS_MNM		"%-8s"
#define FMT_INS_OPR		"%-12s"
#define FMT_INS			FMT_INS_MNM " " FMT_INS_OPR " " FMT_INS_OPR " " FMT_INS_OPR " " FMT_INS_OPR

// Billion dollar company yes? (::fix_parameter throws a warning otherwise.)
//
#ifdef __INTEL_COMPILER
	#pragma warning (disable:1011)
#endif

namespace vtil::format
{
	// Suffixes used to indicate registers of N bytes.
	//
	static constexpr char suffix_map[] = { ' ', 'b', 'w', ' ', 'd', ' ', ' ', ' ', 'q' };

	// Used to fix std::string usage in combination with "%s".
	//
	template<typename T>
	__forceinline static auto fix_parameter( T&& x )
	{
		if constexpr ( std::is_same_v<std::remove_cvref_t<T>, std::string> || std::is_same_v<std::remove_cvref_t<T>, std::wstring> )
			return x.data();
		else
			return std::forward<T>( x );
	}

	// Returns formatted string according to <fms>.
	//
	template<typename... params>
	static std::string str( const char* fmt, params&&... ps )
	{
		std::string buffer;
		buffer.resize( snprintf( nullptr, 0, fmt, fix_parameter<params>( std::forward<params>( ps ) )... ) );
		sprintf_s( buffer.data(), buffer.size() + 1, fmt, fix_parameter<params>( std::forward<params>( ps ) )... );
		return buffer;
	}

	// Formats the integer into a signed hexadecimal.
	//
	template<typename T, std::enable_if_t<std::is_integral_v<std::remove_cvref_t<T>>, int> = 0>
	static std::string hex( T&& value )
	{
		if ( !std::is_signed_v<std::remove_cvref_t<T>> || value >= 0 )
			return str( "0x%llx", value );
		else
			return str( "-0x%llx", -value );
	}

	// Formats the integer into a signed hexadecimal with explicit + if positive.
	//
	inline static std::string offset( int64_t value )
	{
		if ( value >= 0 )
			return str( "+ 0x%llx", value );
		else
			return str( "- 0x%llx", -value );
	}
};