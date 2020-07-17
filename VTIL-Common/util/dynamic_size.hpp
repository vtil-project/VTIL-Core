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
#include <concepts>

namespace vtil
{
	// Determines whether the object is random-accessable by definition or not.
	//
	template<typename T> 
	concept DefaultRandomAccessible = requires( T v ) { v[ 0 ]; std::size( v ); };

	// Determines whether the object implements a custom random-access interface.
	//
	template<typename T> 
	concept CustomRandomAccessible = requires( T v ) { v[ 0 ]; v.size(); };

	// Disjunction of both constraints.
	//
	template<typename T>
	concept RandomAccessible = DefaultRandomAccessible<T> || CustomRandomAccessible<T>;

	// Gets the size of the given container, 0 if N/A.
	//
	template<typename T>
	static constexpr size_t dynamic_size( T&& o )
	{
		if constexpr ( DefaultRandomAccessible<T> )
			return std::size( o );
		else if constexpr ( CustomRandomAccessible<T> )
			return o.size();
		return 0;
	}

	// Gets the Nth element from the object.
	//
	template<RandomAccessible T>
	static constexpr decltype( auto ) deref_n( T&& o, size_t N ) 
	{ 
		return o[ N ]; 
	}
};