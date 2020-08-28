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
#include <algorithm>
#include <variant>
#include <optional>
#include "intrinsics.hpp"
#include "type_helpers.hpp"
#include "lt_typeid.hpp"
#include "../io/formatting.hpp"
#include "fnv64.hpp"

namespace vtil
{
	// Declare hash type.
	//
	#define VTIL_HASH_SIZE 64
	using hash_t = vtil::fnv64_hash_t;

	// VTIL hashable types implement [hash_t T::hash() const];
	//
	template<typename T>
	concept CustomHashable = requires( T v ) { v.hash(); };
	template<typename T>
	concept CxprReducable = requires( T v ) { v.template cxreduce<true>(); };

	// Checks if std::hash is specialized to hash the type.
	//
	template<typename T>
	concept StdHashable = requires( T v ) { std::hash<T>{}( v ); };

	// This tag is used to simplify the use of hasher struct when passing to
	// classic STL templates that take a type-tagged hasher, will redirect all
	// instances of operator() to the default hasher as decided by make_hash(...).
	//
	struct hasher_proxy_t {};

	namespace impl
	{
		static constexpr uint64_t hash_combination_keys[] =
		{
			0x0c214449f2ced59a, 0x63799bb9f17566b6,	0xbccb2d46778c06d1, 0x4570d058141eca81,
			0xca967987832ab9dd, 0xff85a956b704b02e,	0xc3544dd4f91272e0, 0xc2f4185a6b5da2fa,
			0x0d2c48be2a8b2eac, 0x10373db6d8fbf237,	0x8c5bbed2074d19a6, 0x4bbf4451b13375dc,
			0xe2bdd40325aee12c, 0x562ed25209bbaabd,	0x8659a830869a89ff, 0x015db8396e1ec55a,
			0xf12189b01704f5a5, 0xf86540ef4910fbbe,	0x482cf76fa1fef848, 0x6e1ba3ffe21ff90d,
			0x870d91d376936b1c, 0x68ad6b317bf548d3,	0x25956f8cf8f61f1e, 0xd1034eeae30b3cff,
			0xf1901e9f69d6b183, 0xc74f6acbc520c43f,	0x4baab0a89021b9e6, 0x432bacb35143cd01,
			0xe2c254956ea60865, 0xc7f7a5570d61009d,	0x05094efaaf889e3b, 0xc118676c1d7b78f7,
			0x0ca0c965b0fd34ef, 0x6dcb98d623b7defc, 0x2edd0e86860ed35a, 0x93785fa8424ec7ce,
			0xa421dd7a455cad94, 0x334d5c6bf23c41a9, 0x101fb5a20dabc5b8, 0xc8dd9d4da0103025,
			0x75c3870304c0b9f6, 0xbd83825458b55edc, 0x730bdb30ebfcf0c2, 0xc52ffe66afbec22b,
			0x9b1581590b90d484, 0xad2698ca617f4940, 0x1f823ccbc35bda50, 0x92717153a167439e,
			0x2e1770b9d19bbdee, 0xc54c7c30a19075a1, 0x4aa6fc19e3b16881, 0x2a76777dfe6ee009,
			0x8ab2f6f54d6f0f3c, 0x252d923185ff895a, 0xc6cf709908708bd5, 0x3d164624c483ff88,
			0x2271b75f2a889123, 0x0b892f4ae4e5f9f5, 0x0095bb746454d0b7, 0xc0e948fe1a9dc9eb,
			0x96b1d69df03265c6, 0xbeac9571cabb01c1, 0x7d9ef1d2fde07fc1, 0x3217c6c2c98498c1,
		};
	};

	// Used to combine two hashes of arbitrary size.
	//
	__forceinline static constexpr hash_t combine_hash( hash_t a, const hash_t& b )
	{
		constexpr auto rotl64 = [ ] ( uint64_t x, int r )
		{
			return ( x << r ) | ( x >> ( 64 - r ) );
		};
		a.value[ 0 ] = rotl64( a.value[ 0 ] + b.value[ 0 ], 21 );
		a.value[ 0 ] -= b.value[ 0 ] ^ impl::hash_combination_keys[ a.value[ 0 ] & 63 ];
		return a;
	}
	__forceinline static constexpr hash_t combine_unordered_hash( hash_t a, const hash_t& b )
	{
		a.value[ 0 ] += b.value[ 0 ];
		a.value[ 0 ] -= impl::hash_combination_keys[ 0 ];
		return a;
	}

	// Define basic hasher.
	//
	template<typename T = hasher_proxy_t>
	struct hasher
	{
		constexpr auto operator()( const T& value ) const noexcept
		{
			// If object is hashable via ::hash(), use as is.
			//
			if constexpr ( CustomHashable<const T&> )
			{
				if ( !std::is_constant_evaluated() || is_constexpr( [ &value ] () { value.hash(); } ) )
				{
					return hash_t{ value.hash() };
				}
				else if constexpr ( CxprReducable<T> )
				{
					auto tuple = value.template cxreduce<true>();
					return hasher<decltype( tuple )>{}( std::move( tuple ) );
				}
			}
			// If STL container or array, hash each element and add container information.
			//
			else if constexpr ( Iterable<const T&> )
			{
				hash_t hash = {};
				size_t i = 0;
				for ( const auto& entry : value )
					hash = combine_hash( hash, hasher<std::decay_t<decltype( entry )>>{}( entry ) ), i++;
				hash.add_bytes( sizeof( T ) + i );
				return hash;
			}
			// If hash, combine with default seed.
			//
			else if constexpr ( std::is_same_v<T, hash_t> )
			{
				return combine_hash( value, {} );
			}
			// If pointer, use a special hasher.
			//
			else if constexpr ( std::is_pointer_v<T> )
			{
				uint64_t identifier = ( ( uint64_t ) value ) & ( ( 1ull << 48 ) - 1 );
				return hash_t{ ( identifier << 16 ) ^ ( identifier ) };
			}
			// If trivial type, hash each byte.
			//
			else if constexpr ( std::is_trivial_v<T> )
			{
				hash_t hash = {};
				hash.add_bytes( value );
				return hash;
			}
			// If hashable using std::hash<>, redirect.
			//
			else if constexpr ( StdHashable<T> )
			{
				return hash_t{ std::hash<T>{}( value ) };
			}
			// Throw assert fail.
			//
			unreachable();
		}
	};

	// Vararg hasher wrapper that should be used to create hashes from N values.
	//
	template<typename T>
	__forceinline static constexpr hash_t make_hash( const T& value ) { return hasher<T>{}( value ); }
	template<typename C, typename... T>
	__forceinline static constexpr hash_t make_hash( const C& current, T&&... rest )
	{
		hash_t hash = make_hash( current );
		( ( hash = combine_hash( hash, make_hash( rest ) ) ), ... );
		return hash;
	}

	// Vararg hasher wrapper that should be used to create hashes from N values, explicitly ignoring the order.
	//
	template<typename T>
	__forceinline static constexpr hash_t make_unordered_hash( const T& value ) { return hasher<T>{}( value ); }
	template<typename C, typename... T>
	__forceinline static constexpr hash_t make_unordered_hash( const C& current, T&&... rest )
	{
		hash_t hash = make_unordered_hash( current );
		( ( hash = combine_unordered_hash( hash, make_unordered_hash( rest ) ) ), ... );
		return hash;
	}

	// Overload for std::optional.
	//
	template<typename T>
	struct hasher<std::optional<T>>
	{
		__forceinline constexpr hash_t operator()( const std::optional<T>& value ) const noexcept
		{
			if ( value ) return make_hash( *value );
			else         return lt_typeid_v<T>;
		}
	};

	// Overload for std::variant.
	//
	template<typename... T>
	struct hasher<std::variant<T...>>
	{
		__forceinline constexpr hash_t operator()( const std::variant<T...>& value ) const noexcept
		{
			hash_t res = std::visit( [ ] ( auto&& arg ) { return make_hash( arg ); }, value );
			res.add_bytes( value.index() );
			return res;
		}
	};

	// Overload for std::pair / std::tuple.
	//
	template<Tuple T>
	struct hasher<T>
	{
		__forceinline constexpr hash_t operator()( const T& obj ) const noexcept
		{
			if constexpr ( std::tuple_size_v<T> != 0 )
				return std::apply( [ ] ( auto&&... params ) { return make_hash( params... ); }, obj );
			else 
				return lt_typeid_v<T>;
		}
	};

	// Overload default instance.
	//
	template<>
	struct hasher<hasher_proxy_t>
	{
		template<typename T>
		__forceinline constexpr size_t operator()( const T& obj ) const noexcept
		{
			return ( size_t ) make_hash( obj ).as64();
		}
	};

	// Disjunction of all possible conversions.
	//
	template<typename T>
	concept Hashable = requires( T v ) { !std::is_void_v<decltype( hasher<>{}( v ) )>; };
};

// Redirect from std::hash.
//
namespace std
{
	template<vtil::CustomHashable T>
	struct hash<T>
	{
		__forceinline constexpr size_t operator()( const T& value ) const noexcept
		{
			return vtil::hash_t{ value.hash() }.as64();
		}
	};
};