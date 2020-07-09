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
#include <type_traits>
#include <stdint.h>

namespace vtil
{
	// This class generates a unique 64-bit hash for each type at link time 
	// with no dependency on compiler features such as RTTI.
	//
	template<typename T>
	class lt_typeid
	{
		// Invoked internally to calculate the final hash.
		//
		static size_t calculate()
		{
			if constexpr ( !std::is_same_v<T, void> )
			{
				// Calculate the distance between the reference point of this type
				// and of void and apply an aribtrary hash function over it. This 
				// should match for all identical binaries regardless of relocations.
				//
				intptr_t reloc_delta = ( intptr_t ) &value - ( intptr_t ) &lt_typeid<void>::value;
				return ( size_t ) ( ( 0x47C63F4156E0EA7F ^ reloc_delta ) * ( sizeof( T ) + reloc_delta | 3 ) );
			}
			return ( size_t ) -1;
		}
	public:
		// Stores the computed hash at process initialization time.
		//
		inline static const size_t value = calculate();
	};

	template<typename T>
	static const size_t& lt_typeid_v = lt_typeid<std::decay_t<T>>::value;
};