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
#include <vtil/math>
#include <vtil/utility>
#include <functional>
#include <stdlib.h>

namespace vtil::symbolic
{
	namespace impl
	{
		// Check if type is hashable using std::hash.
		//
		template<typename... D>
		struct is_hashable : concept_base<is_hashable, D...>
		{
			template<typename T>
			static auto f( T v ) -> decltype( std::hash<std::remove_cvref_t<T>>{}( v ) );
		};

		// Check if type is convertable to string using std::to_string.
		//
		template<typename... D>
		struct std_to_string : concept_base<std_to_string, D...>
		{
			template<typename T>
			static auto f( T v ) -> decltype( std::to_string( v ) );
		};

		// Check if type is convertable to string using T.to_string()
		//
		template<typename... D>
		struct has_to_string : concept_base<has_to_string, D...>
		{
			template<typename T>
			static auto f( T v ) -> decltype( v.to_string() );
		};
	};

	// Unique identifier type to be used within symbolic expression context.
	//
	struct unique_identifier
	{
		// Identifier stored as variant.
		//
		variant value;

		// String cast of the stored type.
		//
		std::function<std::string( const variant& )> string_cast;

		// Three-way comperator of the stored type.
		//
		int( *compare_value )( const unique_identifier&, const unique_identifier& );

		// Hash of the identifier.
		//
		size_t hash;

		// Default constructor/copy/move.
		//
		unique_identifier() : value( std::nullopt ) {};
		unique_identifier( unique_identifier&& ) = default;
		unique_identifier& operator=( unique_identifier&& ) = default;
		unique_identifier( const unique_identifier& ) = default;
		unique_identifier& operator=( const unique_identifier& ) = default;

		// Construct from a string.
		//
		template<typename hasher_t = std::hash<std::string>>
		unique_identifier( std::string name ) : value( std::move( name ) )
		{
			// Calculate hash using hasher.
			//
			hash = hasher_t{}( name );

			// Move string into string_cast capture to return as is.
			//
			string_cast = [ ] ( const variant& v ) { return v.get<std::string>(); };

			// Set comparison operator.
			//
			compare_value = [ ] ( const unique_identifier& a, const unique_identifier& b )
			{
				return a.to_string().compare( b.to_string() );
			};
		}

		// Construct from any other type.
		//
		template<typename T, 
			// If std::hash<T> is defined, standard hasher, else void.
			typename hasher_t = std::conditional_t<impl::is_hashable<T>::apply(), std::hash<T>, void>,
			// Must not be an array or [const unique_identifier&].
			std::enable_if_t<!std::is_same_v<T, unique_identifier> && !std::extent_v<T>, int> = 0>
			unique_identifier( const T& v, std::string&& name = "" ) : value( v )
		{
			// If name is provided, redirect string_cast to it.
			//
			if ( !name.empty() )
			{
				string_cast = [ name ] ( auto& ) { return name; };
			}
			// Otherwise try to name the variable.
			//
			else
			{
				// If has ::to_string(), redirect.
				//
				if constexpr ( impl::has_to_string<T>::apply() )
				{
					string_cast = [  ] ( const variant& v ) { return v.get<T>().to_string(); };
				}
				// If std::to_string is valid, redirect.
				//
				else if constexpr ( impl::std_to_string<T>::apply() )
				{
					string_cast = [  ] ( const variant& v ) { return std::to_string( v.get<T>() ); };
				}
				// Otherwise assert we have a valid hasher.
				//
				else
				{
					string_cast = [ ] ( const variant& v ) { return "[object]"; };
					static_assert( !std::is_same_v<hasher_t, void>, "Unique identifier was not provided a hasher nor a way to acquire the name." );
				}
			}

			// Set comparison operator.
			//
			compare_value = [ ] ( const unique_identifier& a, const unique_identifier& b )
			{
				auto& ta = a.get<T>();
				auto& tb = b.get<T>();
				if ( ta == tb ) return  0;
				if ( ta < tb )  return -1;
				else            return +1;
			};

			// If we don't have a hasher, hash the name.
			//
			if constexpr ( std::is_same_v<hasher_t, void> )
				hash = std::hash<std::string>{}( to_string() );

			// Otherwise use the hasher.
			//
			else
				hash = hasher_t{}( v );

			// Store value as a variant.
			//
			value = v;
		}

		// Gets the value stored by this structure.
		//
		template<typename T, typename R = std::conditional_t<std::is_same_v<T, std::string>, T, const T&>>
		R get() const
		{
			// Strings are stored as capture lambdas.
			//
			if constexpr ( std::is_same_v<T, std::string> )
				return string_cast( value );

			// Rest are redirected to variant.
			//
			else
				return value.get<T>();
		}

		// Conversion to human-readable format.
		// - Note: Will cache the return value in string_cast as lambda capture if non-const-qualified.
		//
		std::string to_string();
		std::string to_string() const;

		// Cast to bool checks if valid or not.
		//
		inline operator bool() const { return value.has_value(); }

		// Simple comparison operators.
		//
		bool operator==( const unique_identifier& o ) const;
		bool operator<( const unique_identifier& o ) const;
		inline bool operator!=( const unique_identifier& o ) const { return !operator==( o ); }
	};
};