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
#include <string_view>
#include "../util/intrinsics.hpp"
#include "../util/type_helpers.hpp"

namespace vtil
{
	// Used to generate names for enum types.
	//
	template<Enum T>
	struct enum_name
	{
		static constexpr int iteration_limit = 64;

		// Type characteristics.
		//
		using value_type = std::underlying_type_t<T>;
		static constexpr bool is_signed = std::is_signed_v<value_type>;
		static constexpr int min_value = is_signed ? -( iteration_limit / 2 ) : 0;
		static constexpr int max_value = is_signed ? +( iteration_limit / 2 ) : ( iteration_limit );
		
		// Generates the name for the given enum.
		//
		template<T Q>
		static constexpr std::pair<std::string_view, bool> generate()
		{
			std::string_view name = const_tag<Q>::name();
			if ( name[ 0 ] == '(' || uint8_t( name[ 0 ] - '0' ) <= 9 )
				return { "", false };
			return { name, true };
		}

		// String conversion at runtime.
		//
		static std::string resolve( T v )
		{
			value_type value = ( value_type ) v;

			// If value within iteration range, try the linear list:
			//
			if ( min_value <= value && value < max_value )
			{
				static constexpr auto linear_series = make_constant_series<iteration_limit>(
					[ ] ( auto tag ) { return generate<T( decltype( tag )::value + min_value )>(); }
				);
				value_type adjusted = value - min_value;
				if ( value_type( 0 ) <= adjusted && adjusted < value_type( iteration_limit ) )
				{
					auto& [str, valid] = linear_series[ adjusted ];
					if ( valid ) return std::string{ str.begin(), str.end() };
				}
			}
			// If not and type is not signed, try interpreting it as a flag combination:
			//
			if constexpr ( !is_signed )
			{
				static constexpr auto flag_series = make_constant_series<sizeof( value_type ) * 8>(
					[ ] ( auto tag ) { return generate<T( 1ull << decltype( tag )::value )>(); }
				);

				std::string name;
				for ( size_t i = 0; value; i++, value >>= 1 )
				{
					if ( value & 1 )
					{
						if ( auto& [str, valid] = flag_series[ i ]; valid ) 
							name += std::string{ str.begin(), str.end() } + "|";
						else                           
							return std::to_string( ( value_type ) v );
					}
				}
				if ( !name.empty() ) return name.substr( 0, name.length() - 1 );
			}
			return std::to_string( value );
		}

		// Dummy constructor and string conversion.
		//
		std::string name;
		enum_name( T v ) : name( resolve( v ) ) {}

		std::string&& to_string() && { return std::move( name ); }
		operator std::string&&()  && { return std::move( name ); }
		const std::string& to_string() const& { return name; }
		operator const std::string&()  const& { return name; }
	};
};