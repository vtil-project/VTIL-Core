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
#include "concept.hpp"

namespace vtil
{
	namespace impl
	{
		// Determines whether the object is random-accessable by definition or not.
		//
		template<typename... D>
		struct is_default_ra : concept_base<is_default_ra, D...>
		{
			template<typename T>
			static auto f( const T& v ) -> decltype( v[ 0 ], std::size( v ) );
		};

		// Determine whether the object is random-accessable by a custom interface or not.
		//
		template<typename... D>
		struct is_cutom_ra : concept_base<is_cutom_ra, D...>
		{
			template<typename T>
			static auto f( const T& v ) -> decltype( v[ 0 ], v.size() );
		};
	};

	// Returns whether the given object is a random-accessable container or not.
	//
	template<typename T>
	static constexpr bool is_random_access_v = 
		impl::is_default_ra<T>::apply() ||
		impl::is_cutom_ra<T>::apply();

	// Gets the size of the given container.
	//
	template<typename T>
	static size_t dynamic_size( T& o )
	{
		if constexpr ( impl::is_default_ra<T>::apply() )
			return std::size( o );
		else if constexpr ( impl::is_cutom_ra<T>::apply() )
			return o.size();
		return 0;
	}

	// Gets the Nth element from the object.
	//
	template<typename T>
	static decltype( std::declval<T&>()[0] ) deref_n( T& o, size_t N )
	{
		return o[ N ];
	}
};