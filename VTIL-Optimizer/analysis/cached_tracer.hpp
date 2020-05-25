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
#include <functional>
#include <map>
#include <vtil/vm>
#include "trace.hpp"

namespace vtil::optimizer
{
    // Tracing is extremely costy and adding a simple cache reduces the cost 
    // by ~100x fold, however we can't use a global cache since the optimizer 
    // will change the instruction stream and all cache will be eventually 
    // invalidated after each optimization pass so we use an instanced cache.
    //
	struct cached_tracer
	{
        // Define the type of the cache.
        //
        using cache_type =  std::unordered_map<symbolic::variable, symbolic::expression::reference, hasher<>>;
        using cache_entry = cache_type::value_type;

        // Declare the lookup map for the cache mapping each variable to the
        // result of the primitive traver.
        //
        cache_type cache;

        // Replicate trace_basic with the addition of a cache lookup.
        //
        symbolic::expression trace_basic_cached( const symbolic::variable& lookup, const trace_function_t& tracer = {} );

        // Wrappers of trace and rtrace with cached basic tracer.
        //
        symbolic::expression trace( const symbolic::variable& lookup, bool pack = true );
        symbolic::expression rtrace( const symbolic::variable& lookup, bool pack = true );

        // Flushes the cache.
        //
        auto flush() { cache.clear(); return *this; }

        // Implicit casting to a trace function.
        //
        operator trace_function_t() { return [ this ] ( auto v ) { return trace_basic_cached( v ); }; }
	};
};