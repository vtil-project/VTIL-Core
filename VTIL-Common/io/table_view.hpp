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
#include <array>
#include <initializer_list>
#include <numeric>
#include <string>
#include <string_view>
#include "../util/type_helpers.hpp"
#include "formatting.hpp"

// Declares a table data renderer.
//
namespace vtil::format
{
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

			for ( auto eit = std::begin( data_source ); eit != std::end( data_source ); ++eit )
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