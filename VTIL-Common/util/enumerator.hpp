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
#include "../io/asserts.hpp"

namespace vtil
{
	// Declares a generic enumerator controller.
	//
	struct enumerator
	{
		// Enumerator can return tagged orders using this type to control the loop.
		//
		struct tagged_order 
		{ 
			bool should_break = false;
			bool global_break = false;
		};
		static constexpr tagged_order obreak =    { .should_break = true,  .global_break = false };
		static constexpr tagged_order obreak_r =  { .should_break = true,  .global_break = true  };
		static constexpr tagged_order ocontinue = { .should_break = false, .global_break = false };

		// Enumeratee should use this function to get order from any callee.
		//
		template<typename T, typename... Tx>
		inline static tagged_order invoke( T&& fn, Tx&&... args )
		{
			using ret_type = decltype( fn( std::declval<Tx&&>()... ) );

			if constexpr ( std::is_same_v<ret_type, void> )
				return fn( std::forward<Tx>( args )... ), ocontinue;
			else if constexpr ( std::is_same_v<ret_type, tagged_order> )
				return fn( std::forward<Tx>( args )... );
			else
				static_assert( sizeof( T ) == -1, "Enumerator should return void or valid order." );
			
			unreachable();
		}
	};
};