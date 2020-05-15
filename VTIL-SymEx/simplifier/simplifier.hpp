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
#include <iterator>
#include <unordered_map>
#include "../expressions/expression.hpp"

// [Configuration]
// Determine whether we should log the details of the simplification process.
//
#ifndef VTIL_SYMEX_SIMPLIFY_VERBOSE
	#define VTIL_SYMEX_SIMPLIFY_VERBOSE 0
#endif

namespace vtil::symbolic
{
	using simplifier_cache_t = std::unordered_map<boxed_expression, std::pair<expression::reference, bool>, hasher<>>;

	// Attempts to simplify the expression given, returns whether the simplification
	// succeeded or not.
	//
	bool simplify_expression( expression::reference& exp, bool pretty = false, int64_t max_depth = -1 );

	// Purges/references the current thread's simplifier cache.
	//
	void purge_simplifier_cache();
	simplifier_cache_t& ref_simplifier_cache();

	// RAII hack to purge the cache once the we're out of scope.
	//
	struct cache_guard
	{
		// Constructor saves the current size of the simplifier cache, dummy argument 
		// we take here is required since the compiler will not invoke this constructor otherwise.
		//
		size_t previous_size = 0;
		cache_guard( bool _ = false )
		{
			previous_size = ref_simplifier_cache().size();
		}

		// Destructor resets simplifier cache to its original size.
		//
		~cache_guard()
		{
			auto& cache = ref_simplifier_cache();
			cache.erase( std::next( cache.begin(), previous_size ), cache.end() );
		}
	};
};