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
#include <string>
#include <cstring>
#include <cstdio>
#include <type_traits>
#include <exception>
#include <optional>
#include <filesystem>
#include <numeric>
#include <string_view>
#include "../util/lt_typeid.hpp"
#include "../util/type_helpers.hpp"
#include "../util/time.hpp"
#include "../util/numeric_iterator.hpp"
#include "../util/intrinsics.hpp"
#include "enum_name.hpp"

// [Configuration]
// Macro wrapping ANSI escape codes, can be replaced by '#define ANSI_ESCAPE(...)' in legacy Windows to disable colors completely.
//
#ifndef ANSI_ESCAPE
	#define ANSI_ESCAPE(...) ("\x1B[" __VA_ARGS__)
#endif

namespace vtil::format
{
	using string_buffer = std::vector<std::string>;

	namespace impl
	{
		// Types that will require no explicit conversion to string when being passed to *printf will pass.
		//
		template<typename T>
		concept ValidFormatStringArgument = 
			std::is_fundamental_v<std::remove_cvref_t<T>> || std::is_enum_v<std::remove_cvref_t<T>>  ||
			std::is_pointer_v<std::remove_cvref_t<T>>     || std::is_array_v<std::remove_cvref_t<T>> || CppString<std::remove_cvref_t<T>>;
	};

	template<typename... Tx> 
	__forceinline static string_buffer create_string_buffer_for()
	{
		string_buffer buffer;
		if constexpr ( sizeof...( Tx ) != 0 )
			buffer.reserve( ( ( impl::ValidFormatStringArgument<Tx> ? 0 : 1 ) + ... ) );
		return buffer;
	}

	namespace impl
	{
		// Fixes the type name to be more friendly.
		//
		inline static std::string fix_type_name( std::string in )
		{
			static const std::string remove_list[] = {
				"struct ",
				"class ",
				"enum ",
				"vtil::"
			};
			for ( auto& str : remove_list )
			{
				if ( in.starts_with( str ) )
					return fix_type_name( in.substr( str.length() ) );

				for ( size_t i = 0; i < in.size(); i++ )
					if ( in[ i ] == '<' && in.substr( i + 1 ).starts_with( str ) )
						in = in.substr( 0, i + 1 ) + in.substr( i + 1 + str.length() );
			}
			return in;
		}
	};

	// Suffixes used to indicate registers of N bytes.
	//
	static constexpr char suffix_map[] = { 0, 'b', 'w', 0, 'd', 0, 0, 0, 'q' };

	// Returns the type name of the object passed, dynamic type name will
	// redirect to static type name if RTTI is not supported.
	//
	template<typename T>
	static std::string static_type_name()
	{
#if HAS_RTTI
		static const std::string res = impl::fix_type_name( compiler_demangle_type_name( typeid( T ) ) );
		return res;
#else
		char buf[ 32 ];
		sprintf_s( buf, "Type%llx", lt_typeid<T>::value );
		return buf;
#endif
	}
	template<typename T>
	static std::string dynamic_type_name( const T& o )
	{
#if HAS_RTTI
		return impl::fix_type_name( compiler_demangle_type_name( typeid( o ) ) );
#else
		return static_type_name<T>();
#endif
	}

	// VTIL string-convertable types implement [std::string T::to_string() const];
	//
	template<typename T>
	concept CustomStringConvertible = requires( T v ) { v.to_string(); };

	// Checks if std::to_string is specialized to convert type into string.
	//
	template<typename T>
	concept StdStringConvertible = requires( T v ) { std::to_string( v ); };

	// Converts any given object to a string.
	//
	template<typename T>
	static auto as_string( const T& x );
	template<typename T>
	concept StringConvertible = requires( std::string res, T v ) { res = as_string( v ); };

	template<typename T>
	__forceinline static auto as_string( const T& x )
	{
		using base_type = std::decay_t<T>;
		
		if constexpr ( CustomStringConvertible<T> )
		{
			return x.to_string();
		}
		else if constexpr ( Enum<T> )
		{
			return enum_name<T>::resolve( x );
		}
		else if constexpr ( Duration<T> )
		{
			return time::to_string( x );
		}
		else if constexpr ( std::is_same_v<base_type, uint64_t> )
		{
			char buffer[ 16 + 3 ];
			return std::string{ buffer, buffer + snprintf( buffer, std::size( buffer ), "0x%llx", x ) };
		}
		else if constexpr ( std::is_same_v<base_type, int64_t> )
		{
			return hex_t<base_type>( x ).to_string();
		}
		else if constexpr ( std::is_same_v<base_type, bool> )
		{
			return x ? "true"s : "false"s;
		}
		else if constexpr ( StdStringConvertible<T> )
		{
			return std::to_string( x );
		}
		else if constexpr ( std::is_base_of_v<std::exception, T> )
		{
			return std::string{ x.what() };
		}
		else if constexpr ( CppString<base_type> || CppStringView<base_type> )
		{
			return std::string{ x.begin(), x.end() };
		}
		else if constexpr ( CString<base_type> )
		{
			return std::string{
				x,
				x + std::char_traits<string_unit_t<base_type>>::length( x )
			};
		}
		else if constexpr ( std::is_same_v<base_type, std::filesystem::directory_entry> )
		{
			return x.path().string();
		}
		else if constexpr ( std::is_same_v<base_type, std::filesystem::path> )
		{
			return x.string();
		}
		else if constexpr ( std::is_pointer_v<base_type> )
		{
			char buffer[ 17 ];
			snprintf( buffer, 17, "%p", x );
			return std::string{ buffer };
		}
		else if constexpr ( is_specialization_v<std::pair, base_type> )
		{
			if constexpr ( StringConvertible<decltype( x.first )> && StringConvertible<decltype( x.second )> )
				return "(" + as_string( x.first ) + ", " + as_string( x.second ) + ")";
			else return type_tag<T>{};
		}
		else if constexpr ( is_specialization_v<std::tuple, base_type> )
		{
			constexpr bool is_tuple_str_cvtable = [ ] ()
			{
				bool cvtable = true;
				if constexpr ( std::tuple_size_v<base_type> > 0 )
				{
					make_constant_series<std::tuple_size_v<base_type>>( [ & ] ( auto tag )
					{
						if constexpr ( !StringConvertible<std::tuple_element_t<decltype( tag )::value, base_type>> )
							cvtable = false;
					} );
				}
				return cvtable;
			}();

			if constexpr ( std::tuple_size_v<base_type> == 0 )
				return "{}"s;
			else if constexpr ( is_tuple_str_cvtable )
			{
				std::string res = std::apply( [ ] ( auto&&... args ) {
					return ( ( as_string( args ) + ", " ) + ... );
				}, x );
				return "{" + res.substr(0, res.length() - 2) + "}";
			}
			else return type_tag<T>{};
		}
		else if constexpr ( is_specialization_v<std::optional, base_type> )
		{
			if constexpr ( StringConvertible<decltype( x.value() )> )
			{
				if ( x.has_value() )
					return as_string( x.value() );
				else
					return "nullopt"s;
			}
			else return type_tag<T>{};
		}
		else if constexpr ( is_specialization_v<std::reference_wrapper, base_type> )
		{
			if constexpr ( StringConvertible<decltype( x.get() )> )
				return as_string( x.get() );
			else return type_tag<T>{};
		}
		else if constexpr ( Iterable<T> )
		{
			if constexpr ( StringConvertible<iterator_value_type_t<T>> )
			{
				std::string items = {};
				for ( auto&& entry : x )
					items += as_string( entry ) + ", "s;
				if ( !items.empty() ) items.resize( items.size() - 2 );
				return "{" + items + "}";
			}
			else return type_tag<T>{};
		}
		else return type_tag<T>{};
	}
	template<typename T, typename... Tx>
	__forceinline static auto as_string( const T& f, const Tx&... r )
	{
		std::string result = as_string( f ) + ", " + as_string( r... );
		result.erase( result.end() - 2, result.end() );
		return result;
	}

	// Used to fix std::(w)string usage in combination with "%(l)s".
	//
	template<typename T>
	__forceinline static auto fix_parameter( string_buffer& buffer, T&& x )
	{
		using base_type = std::remove_cvref_t<T>;

		// If fundamental type, return as is.
		//
		if constexpr ( std::is_fundamental_v<base_type> || std::is_enum_v<base_type> || 
					   std::is_pointer_v<base_type> || std::is_array_v<base_type> )
		{
			return x;
		}
		// If it is a basic string:
		//
		else if constexpr ( CppString<base_type> )
		{
			return x.data();
		}
		// If string convertible:
		//
		else if constexpr ( StringConvertible<T> )
		{
			return buffer.emplace_back( as_string( std::forward<T>( x ) ) ).data();
		}
		// If none matched, forcefully convert into [type @ pointer].
		//
		else
		{
			return buffer.emplace_back( "[" + dynamic_type_name( x ) + "@" + as_string( &x ) + "]" ).data();
		}
	}

	// Returns formatted string according to <fms>.
	//
	template<typename... Tx>
	static std::string str( const char* fmt, Tx&&... ps )
	{
		auto print_to_buffer = [ ] ( const char* fmt, auto&&... args )
		{
			std::string buffer( 128, ' ' );
			buffer.resize( snprintf( buffer.data(), buffer.size() + 1, fmt, args... ) );
			if ( buffer.size() >= 128 )
				snprintf( buffer.data(), buffer.size() + 1, fmt, args... );
			return buffer;
		};
		auto buf = create_string_buffer_for<Tx...>();
		return print_to_buffer( fmt, fix_parameter<Tx>( buf, std::forward<Tx>( ps ) )... );
	}

	// Formats the integer into a signed hexadecimal.
	//
	template<Integral T>
	static std::string hex( T value )
	{
		if constexpr ( !std::is_signed_v<T> )
		{
			return str( "0x%llx", value );
		}
		else
		{
			if ( value >= 0 ) return str( "0x%llx", value );
			else              return str( "-0x%llx", -value );
		}
	}

	// Formats the integer into a signed hexadecimal with explicit + if positive.
	//
	inline static std::string offset( int64_t value )
	{
		if ( value >= 0 ) return str( "+ 0x%llx", value );
		else              return str( "- 0x%llx", -value );
	}
};
#undef HAS_RTTI

// Export the concepts.
//
namespace vtil
{
	using format::CustomStringConvertible;
	using format::StdStringConvertible;
	using format::StringConvertible;
};
