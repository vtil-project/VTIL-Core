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
#include <vtil/symex>
#include <unordered_map>
#include <shared_mutex>
#include "tracer.hpp"
#include "../symex/variable.hpp"

namespace vtil
{
    // Tracing is extremely costy and adding a simple cache reduces the cost 
    // by ~100x fold, so this class creates a local cache that gets looked 
    // up before the actual trace operation is executed.
    //
	struct cached_tracer : tracer
	{
        // Define the type of the cache.
        //
        using cache_type =  std::unordered_map<symbolic::variable, symbolic::expression::reference, hasher<>>;
        using cache_entry = cache_type::value_type;

        // Declare the lookup map for the cache mapping each variable to the
        // result of the primitive traver.
        //
        cache_type cache;
        
        // Locks the cache.
        //
        std::shared_mutex mtx;

        // Hooks default tracer and does a cache lookup before invokation.
        //
        symbolic::expression trace( symbolic::variable lookup ) override;

        // Flushes the cache.
        //
        void flush() { cache.clear(); }
        void flush( basic_block* blk )
        {
            for ( auto it = cache.begin(); it != cache.end(); )
            {
                if ( it->first.at.container == blk )
                    it = cache.erase( it );
                else
                    it++;
            }
        }
	};
};