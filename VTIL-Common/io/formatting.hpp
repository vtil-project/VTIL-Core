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
#include "enum_name.hpp"

#ifdef __GNUG__
	#include <cxxabi.h>
#endif

// [Configuration]
// Determine the way we format the instructions.
//
#ifndef VTIL_FMT_DEFINED
	#define VTIL_FMT_INS_MNM	"%-8s"
	#define VTIL_FMT_INS_OPR	"%-12s"
	#define VTIL_FMT_INS_MNM_S	8
	#define VTIL_FMT_INS_OPR_S	12
	#define VTIL_FMT_SUFFIX_1	'b'
	#define VTIL_FMT_SUFFIX_2	'w'
	#define VTIL_FMT_SUFFIX_4	'd'
	#define VTIL_FMT_SUFFIX_8	'q'
	#define VTIL_FMT_DEFINED
#endif

namespace vtil::format
{
	namespace impl
	{
		// Returns a temporary but valid const (w)char* for the given std::(w)string.
		//
		template<typename T>
		static T* buffer_string( std::basic_string<T>&& value )
		{
			static thread_local size_t index = 0;
			static thread_local std::basic_string<T> ring_buffer[ 32 ];
			
			auto& ref = ring_buffer[ index ];
			ref = std::move( value );
			index = ++index % std::size( ring_buffer );
			return ref.data();
		}

		// Fixes the type name to be more friendly.
		//
		static std::string fix_type_name( std::string in )
		{
#ifdef __GNUG__
			int status;
			char* demangled_name = abi::__cxa_demangle( in.data(), nullptr, nullptr, &status );
			// If demangling succeeds, set the name.
			//
			if ( status == 0 )
			{
				in = demangled_name;
			}
			// Free unconditionally.
			//
			free( demangled_name );
#endif
			
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

	// Special type tags for integer formatting.
	//
	template<Integral T, bool hex>
	struct strongly_formatted_integer
	{
		T value = 0;
		constexpr strongly_formatted_integer() {}
		constexpr strongly_formatted_integer( T value ) : value( value ) {}
		constexpr operator T& ( ) { return value; }
		constexpr operator const T& ( ) const { return value; }

		std::string to_string() const
		{
			// Pick the base format.
			//
			const char* fmts[] = { "0x%llx", "-0x%llx", "%llu", "-%llu" };
			size_t fidx = hex ? 0 : 2;

			// Adjust format if needed, find absolute value to use.
			//
			uint64_t r;
			if ( std::is_signed_v<T> && value < 0 ) r = ( uint64_t ) -int64_t( value ), fidx++;
			else                                    r = ( uint64_t ) value;

			// Allocate buffer [ 3 + log_b(2^64) ], write to it and return.
			//
			char buffer[ ( hex ? 16 : 20 ) + 3 ];
			return std::string{ buffer, buffer + snprintf( buffer, std::size( buffer ), fmts[ fidx ], r ) };
		}
	};
	template<Integral T> using hex_t = strongly_formatted_integer<T, true>;
	template<Integral T> using dec_t = strongly_formatted_integer<T, false>;

	// Special type tag for memory/file size formatting.
	//
	template<Integral T = size_t>
	struct byte_count_t
	{
		static constexpr std::array unit_abbrv = { "b", "kb", "mb", "gb", "tb" };

		T value = 0;
		constexpr byte_count_t() {}
		constexpr byte_count_t( T value ) : value( value ) {}
		constexpr operator T&() { return value; }
		constexpr operator const T&() const { return value; }

		std::string to_string() const
		{
			// Convert to double.
			//
			double fvalue = ( double ) value;

			// Iterate unit list in descending order.
			//
			for ( auto [abbrv, i] : backwards( zip( unit_abbrv, iindices ) ) )
			{
				double limit = pow( 1024.0, i );

				// If value is larger than the unit given or if we're at the last unit:
				//
				if ( std::abs( fvalue ) >= limit || abbrv == *std::begin( unit_abbrv ) )
				{
					// Convert float to string.
					//
					char buffer[ 32 ];
					snprintf( buffer, 32, "%.2lf%s", fvalue / limit, abbrv );
					return buffer;
				}
			}
			unreachable();
		}
	};

	// Special type tag for character formatting.
	//
	template<typename T = char>
	struct strong_character_t
	{
		T value = 0;
		constexpr strong_character_t() {}
		constexpr strong_character_t( T value ) : value( value ) {}
		constexpr operator T& ( ) { return value; }
		constexpr operator const T& ( ) const { return value; }

		std::string to_string() const
		{
			return std::string( 1, ( char ) value );
		}
	};

	// Suffixes used to indicate registers of N bytes.
	//
	static constexpr char suffix_map[] = { 0, VTIL_FMT_SUFFIX_1, VTIL_FMT_SUFFIX_2, 0, VTIL_FMT_SUFFIX_4, 0, 0, 0, VTIL_FMT_SUFFIX_8 };

	// Returns the type name of the object passed, dynamic type name will
	// redirect to static type name if RTTI is not supported.
	//
	template<typename T>
	static std::string static_type_name()
	{
#if HAS_RTTI
		static const std::string res = impl::fix_type_name( typeid( T ).name() );
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
		return impl::fix_type_name( typeid( o ).name() );
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
	concept StringConvertible = requires( T v ) { !is_specialization_v<type_tag, decltype( as_string( v ) )>; };

	template<typename T>
	static auto as_string( const T& x )
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
			return std::string{ x ? "true" : "false" };
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
			{
				return "(" + as_string( x.first ) + ", " + as_string( x.second ) + ")";
			}
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
				return "{}";
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
					return std::string{ "nullopt" };
			}
			else return type_tag<T>{};
		}
		else if constexpr ( Iterable<T> )
		{
			if constexpr ( StringConvertible<decltype( *std::begin( x ) )> )
			{
				std::string items = {};
				for ( auto&& entry : x )
					items += as_string( entry ) + ", ";
				if ( !items.empty() ) items.resize( items.size() - 2 );
				return "{" + items + "}";
			}
			else return type_tag<T>{};
		}
		else return type_tag<T>{};
	}

	// Used to fix std::(w)string usage in combination with "%(l)s".
	//
	template<typename T>
	inline static auto fix_parameter( T&& x )
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
		else if constexpr ( std::is_same_v<base_type, std::string> || std::is_same_v<base_type, std::wstring> )
		{
			// If it is a reference, invoke ::data()
			//
			if constexpr ( std::is_reference_v<T> )
				return x.data();
			// Otherwise call buffer helper.
			//
			else
				return impl::buffer_string( std::move( x ) );
		}
		// If string convertible:
		//
		else if constexpr ( StringConvertible<T> )
		{
			return impl::buffer_string( as_string( std::forward<T>( x ) ) );
		}
		// If none matched, forcefully convert into [type @ pointer].
		//
		else
		{
			char buffer[ 32 ];
			snprintf( buffer, 32, "%p", &x );
			return impl::buffer_string( "[" + dynamic_type_name( x ) + "@" + std::string( buffer ) + "]" );
		}
	}

	// Returns formatted string according to <fms>.
	//
	template<typename... params>
	static std::string str( const char* fmt, params&&... ps )
	{
		std::string buffer;
		buffer.resize( snprintf( nullptr, 0, fmt, fix_parameter( ps )... ) );
		snprintf( buffer.data(), buffer.size() + 1, fmt, fix_parameter<params>( std::forward<params>( ps ) )... );
		return buffer;
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
	static std::string offset( int64_t value )
	{
		if ( value >= 0 ) return str( "+ 0x%llx", value );
		else              return str( "- 0x%llx", -value );
	}

	// Table renderer configuration.
    //
    struct table_rendering_configuration
    {
        char vertical_delimiter =   '|';
        char horizontal_delimiter = '-';
        size_t left_pad =           0;
        size_t right_pad =          0;
		size_t max_entries =        std::numeric_limits<size_t>::max();
		size_t field_max_length =   std::numeric_limits<size_t>::max();
    };

    // Declare table structure, data source container must hold a tuple with
    // every element being string convertible by ::as_string.
    //
    template<Iterable C> requires( Tuple<iterator_value_type_t<C>> && 
                                   StringConvertible<C> )
    struct table_view
    {
        // Required typedefs.
        //
        using entry_type_t = iterator_value_type_t<C>;
        
        // Declare field count.
        //
        static constexpr size_t field_count = std::tuple_size_v<iterator_value_type_t<C>>;
        
        // Takes a data source, a list of labels, and optionally rendering configuration.
        //
        C&& data_source;
		table_rendering_configuration config;
		std::array<std::string_view, field_count> labels;
		
		constexpr table_view( C&& data_source, std::array<std::string_view, field_count> labels, table_rendering_configuration config = {} )
            : data_source( std::forward<C>( data_source ) ), labels( std::move( labels ) ), config( std::move( config ) ) {}

        // Declare string conversion.
        //
        std::string to_string() const
        {
            // Determine entry count.
            //
            const size_t entry_count = std::size( data_source );

            // Convert fields in each entry into string and resize if over limit.
            //
            std::vector<std::array<std::string, field_count>> string_entries;
			string_entries.reserve( entry_count );

			for ( auto eit = std::begin( data_source ); eit != std::end( data_source ); eit++ )
			{
				auto& output = string_entries.emplace_back();
				make_constant_series<field_count>( [ & ] ( auto tag )
				{
					auto at = []( auto&& x ) -> auto& { return std::get<decltype( tag )::value>( x ); };
					std::string& str = output[ decltype( tag )::value ];

					str = as_string( at( *eit ) );
					if ( str.length() > config.field_max_length )
					{
						str.resize( config.field_max_length );
						if ( config.field_max_length > 3 )
							std::fill_n( str.end() - 3, 3, '.' );
					}
				} );

				// Break if limit reached.
				//
				if ( string_entries.size() > config.max_entries )
					break;
			}

            // Determine field lengths.
            //
            std::array<size_t, field_count> field_lengths;
            for ( auto [len, label] : zip( field_lengths, labels ) )
                len = label.length();
            for ( auto& fields : string_entries )
            {
                for ( auto [len, label] : zip( field_lengths, fields ) )
                    len = std::max( len, label.length() );
            }

            // Allocate a buffer for the output.
            //
			const bool table_overflow = string_entries.size() != entry_count;
            const size_t line_length = 
                /* field data */ std::accumulate( field_lengths.begin(), field_lengths.end(), 0ull ) + 
                /* delimiters */ 2 + field_count * 3 - 1 +
                /* new line   */ 1;
            const size_t line_count = 
				/* active entries */ string_entries.size() + 
				/* labels         */ 1 + 
				/* delimiters     */ 3 + table_overflow;
            
            std::string result( line_count * ( line_length + config.left_pad + config.right_pad ), '\0' );
            
            // Declare the iterator and data primitives.
            //
            auto iterator = result.begin();
            auto write =   [ & ] ( auto... cs )                { ( ( *iterator++ = cs ), ... ); };
            auto write_n = [ & ] ( const std::string_view& v ) { iterator = std::copy( v.begin(), v.end(), iterator ); };
            auto fill =    [ & ] ( char c, size_t n )          { iterator = std::fill_n( iterator, n, c ); };
            auto begl =    [ & ] ()                            { fill( ' ', config.left_pad ); };
            auto rendl =   [ & ] ()                            { fill( ' ', config.right_pad ); *( iterator - 1 ) = '\n'; };

            // Declare helpers for writing lines.
            //
            auto write_table_limit = [ & ] ()
            {
                begl();
                fill( config.horizontal_delimiter, line_length );
                rendl();
            };
            auto write_fields = [ & ] ( const auto& fields )
            {
                begl();
                write( config.vertical_delimiter, ' ' );
                for ( auto [field, len] : zip( fields, field_lengths ) )
                {
                    auto end_real = iterator + len;
                    write_n( field );
                    if ( end_real > iterator )
                        fill( ' ', end_real - iterator );
                    write( ' ', config.vertical_delimiter, ' ' );
                }
                rendl();
            };
            auto write_label_delim = [ & ] ()
            {
                begl();
                write( config.vertical_delimiter, config.horizontal_delimiter );
                for ( size_t field_len : field_lengths )
                {
                    fill( config.horizontal_delimiter, field_len );
                    write( config.horizontal_delimiter, config.vertical_delimiter, config.horizontal_delimiter );
                }
                rendl();
            };
			auto write_overflow_delim = [ & ] ()
			{
				if ( table_overflow )
				{
					begl();
					write( config.vertical_delimiter, ' ', '.', '.', '.' );
					fill( ' ', line_length - 7 );
					write( config.vertical_delimiter, ' ' );
					rendl();
				}
			};

            // Format the whole table and return the result.
            //
            write_table_limit();
            write_fields( labels );
            write_label_delim();
            for( auto& fields : string_entries )
                write_fields( fields );
			write_overflow_delim();
            write_table_limit();
            return result;
        }
    };

    // Declare deduction guide.
    //
    template<typename C> table_view( C&&, std::initializer_list<std::string_view> )->table_view<C>;
	template<typename C> table_view( C&&, std::initializer_list<std::string_view>, table_rendering_configuration )->table_view<C>;
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
