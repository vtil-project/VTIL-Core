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
#include <iterator>
#include <unordered_map>
#include <memory>
#include "../expressions/expression.hpp"

// [Configuration]
// Determine whether we should log the details of the simplification process.
//
#ifndef VTIL_SYMEX_SIMPLIFY_VERBOSE
	#define VTIL_SYMEX_SIMPLIFY_VERBOSE 0
#endif

// [Configuration]
// Determine the depth limit after which we start self generated signature matching
// properties of the LRU cache and whether simplifications are verified or not.
//
#ifndef VTIL_SYMEX_SELFGEN_SIGMATCH_DEPTH_LIM
	#define	VTIL_SYMEX_SELFGEN_SIGMATCH_DEPTH_LIM   4
#endif
#ifndef VTIL_SYMEX_LRU_CACHE_SIZE
	#define VTIL_SYMEX_LRU_CACHE_SIZE               0x18000
#endif
#ifndef VTIL_SYMEX_LRU_PRUNE_COEFF
	#define VTIL_SYMEX_LRU_PRUNE_COEFF              0.2f
#endif
#ifndef VTIL_SYMEX_HASH_COLLISION_MAX
	#define VTIL_SYMEX_HASH_COLLISION_MAX           8
#endif
#ifndef VTIL_SYMEX_VERIFY
	#ifdef _DEBUG
		#define	VTIL_SYMEX_VERIFY                   1
	#else
		#define	VTIL_SYMEX_VERIFY                   0
	#endif
#endif

namespace vtil::symbolic
{
	// Attempts to simplify the expression given, returns whether the simplification
	// succeeded or not.
	//
	bool simplify_expression( expression::reference& exp, bool pretty = false, bool unpack = true );
};