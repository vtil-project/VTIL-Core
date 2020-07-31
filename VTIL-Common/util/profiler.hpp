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
#include <chrono>
#include <type_traits>

namespace vtil
{
	// Times the callable given and returns pair [result, duration] if it has 
	// a return value or just [duration].
	//
	template<typename T, typename... Tx>
	static auto profile( T&& f, Tx&&... args )
	{
		using result_t = decltype( std::declval<T>()( std::forward<Tx>( args )... ) );

		if constexpr ( std::is_same_v<result_t, void> )
		{
			auto t0 = std::chrono::steady_clock::now();
			f( std::forward<Tx>( args )... );
			auto t1 = std::chrono::steady_clock::now();
			return t1 - t0;
		}
		else
		{

			auto t0 = std::chrono::steady_clock::now();
			result_t res = f();
			auto t1 = std::chrono::steady_clock::now();
			return std::make_pair( res, t1 - t0 );
		}
	}

	// Same as ::profile but ignores the return value and runs N times.
	//
	template<size_t N, typename T, typename... Tx>
	static auto profile_n( T&& f, Tx&&... args )
	{
		auto t0 = std::chrono::steady_clock::now();
		for ( size_t i = 0; i != N; i++ ) 
			f( args... ); // Not forwarded since we can't move N times.
		auto t1 = std::chrono::steady_clock::now();
		return t1 - t0;
	}
};