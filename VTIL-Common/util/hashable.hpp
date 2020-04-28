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
#include <algorithm>
#include <array>
#include "concept.hpp"
#include "..\io\formatting.hpp"


// Determine the size of vtil::hash_t.
//
#ifndef VTIL_HASH_SIZE
	#ifdef _DEBUG
		#define VTIL_HASH_SIZE 64
	#else
		#define VTIL_HASH_SIZE 128
	#endif
#endif


// Include the hash header file for the hash type we use
// and redirect the definition of hash_t to it.
//
#if VTIL_HASH_SIZE == 128
	#include "fnv128.hpp"
	using hash_t = vtil::fnv128_hash_t;
#elif VTIL_HASH_SIZE == 64
	#include "fnv64.hpp"
	using hash_t = vtil::fnv64_hash_t;
#else
	#error FNV-1 Algorithm for the FNV algorithm is not defined for the given bit count.
#endif

namespace vtil
{
	// Default hasher of VTIL objects, the type should export a public 
	// function with the signature [hash_t hash() const].
	//
	template<typename T>
	struct hash
	{
		hash_t operator()( const T& value ) const { return value.hash(); }
	};

	// Check if type is hashable using std::hash.
	//
	template<typename... D>
	struct is_std_hashable : concept_base<is_std_hashable, D...>
	{
		template<typename T>
		static auto f( T v ) -> decltype( std::hash<std::remove_cvref_t<T>>{}( v ) );
	};

	// Check if type is hashable using vtil::hash.
	//
	template<typename... D>
	struct is_vtil_hashable : concept_base<is_vtil_hashable, D...>
	{
		template<typename T>
		static auto f( const T v ) -> std::enable_if_t<std::is_same_v<decltype( v.hash() ), hash_t>>;
	};

	// Checks if the type is hashable using any hasher.
	//
	template<typename T>
	constexpr bool is_hashable_v = is_vtil_hashable<T>::apply() || is_std_hashable<T>::apply();

	// Resolves the default hasher of the type, void if none.
	//
	template<typename T>
	using default_hasher_t =
		std::conditional_t<is_vtil_hashable<T>::apply(), vtil::hash<T>,
		std::conditional_t<is_std_hashable<T>::apply(), std::hash<T>, void>>;
};