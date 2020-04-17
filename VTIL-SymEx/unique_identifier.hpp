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
#include <vtil/memory>

namespace vtil::symbolic
{
	namespace impl
	{
		// Check if type is hashable using std::hash.
		//
		template <typename T>
		static constexpr bool _is_std_hashable( ... ) { return false; }
		template <typename T, typename = decltype( std::declval<std::hash<T>>()( std::declval<T>() ) )>
		static constexpr bool _is_std_hashable( bool v ) { return true; }

		template <typename T>
		static constexpr bool is_std_hashable_v = _is_std_hashable<std::remove_cvref_t<T>>( true );
	};

	// Unique identifier type to be used within symbolic expression context.
	//
#pragma pack(push, 1)
	struct unique_identifier
	{
		// Any 64-bit value that uniquely identifies this symbol.
		//
		union
		{
			size_t hash;
			const void* ptr;
		};

		// Whether we have a valid instance or not.
		//
		bool set;

		// Default and copy constructors.
		//
		unique_identifier() : set( false ) {};
		unique_identifier( unique_identifier&& ) = default;
		unique_identifier( const unique_identifier& ) = default;
		unique_identifier& operator=( unique_identifier&& ) = default;
		unique_identifier& operator=( const unique_identifier& ) = default;

		// Construct from arbitrary value and its hasher. Uses default std::hash<> if not pointer.
		//
		template<typename T, typename hasher_t = std::enable_if_t<!std::is_pointer_v<T> && impl::is_std_hashable_v<T>, std::hash<T>>>
		unique_identifier( const T& value ) : hash( hasher_t{}( value ) ), set( true ) {}

		// Construct from pointer type.
		//
		unique_identifier( const void* p ) : ptr( p ), set( true ) {}

		// Cast to bool checks if valid or not.
		//
		operator bool() const { return set; }

		// Implement comparison operators.
		// - Equals operator always returns false if not set.
		// - Relative comparison considers the set side greater.
		//
		bool operator==( const unique_identifier& o ) const { return set && o.set && hash == o.hash; }
		bool operator!=( const unique_identifier& o ) const { return !operator==( o ); }
		bool operator<( const unique_identifier& o ) const { return ( o.set && !set ) || hash < o.hash; }
	};
#pragma pack(pop)
};