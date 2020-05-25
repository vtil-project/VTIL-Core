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
#include "cached_tracer.hpp"

namespace vtil::optimizer
{
   // Replicate trace_basic with the addition of a cache lookup.
    //
    symbolic::expression cached_tracer::trace_basic_cached( const symbolic::variable& lookup, const trace_function_t& tracer )
    {
        using namespace logger;

#if VTIL_OPT_TRACE_VERBOSE
        // Log the beginning of the trace.
        //
        log<CON_BRG>( "CcTrace(%s)\n", lookup );
        scope_padding _p( 1 );
#endif
        // Handle base case.
        //
        if ( lookup.at.is_begin() )
        {
            symbolic::expression result = lookup.to_expression();
#if VTIL_OPT_TRACE_VERBOSE
            // Log result.
            //
            log<CON_BRG>( "= %s [Base case]\n", result );
#endif
            return result;
        }

        // Try lookup the exact variable in the map in a fast manner.
        //
        auto it = cache.find( lookup );
        if ( it != cache.end() )
        {
            const symbolic::expression& result = *it->second;
#if VTIL_OPT_TRACE_VERBOSE
            // Log result.
            //
            log<CON_BLU>( "= %s [Cached result]\n", result );
#endif
            return result;
        }
        // Declare a predicate for the search of the variable in the cache.
        //
        std::function<bool( const cache_entry& )> predicate;

        // If memory variable:
        //
        if ( lookup.is_memory() )
        {
            predicate = [ & ] ( const cache_entry& pair )
            {
                // Key must be of memory type at the same position.
                //
                if ( !pair.first.is_memory() ) return false;
                if ( pair.first.at != lookup.at ) return false;

                // Must be the same pointer and have a larger or equal size.
                //
                auto& self = lookup.mem();
                auto& other = pair.first.mem();
                return self.decay().equals( other.decay() ) &&
                       self.bit_count >= other.bit_count;
            };
        }
        // If register variable:
        //
        else
        {
            fassert( lookup.is_register() );
            predicate = [ & ] ( const cache_entry& pair )
            {
                // Key must be of memory type at the same position.
                //
                if ( !pair.first.is_register() ) return false;
                if ( pair.first.at != lookup.at ) return false;

                // Must be the same register and have a larger or equal size.
                //
                auto& self = lookup.reg();
                auto& other = pair.first.reg();
                return self.flags == other.flags &&
                       self.local_id == other.local_id &&
                       self.bit_offset == other.bit_offset &&
                       self.bit_count >= other.bit_count;
            };
        }

        // Search the map, if we find a matching entry shrink and use as the result.
        //
        symbolic::expression result;
        it = std::find_if( cache.begin(), cache.end(), predicate );
        if ( it != cache.end() )
            result = symbolic::expression{ *it->second }.resize( lookup.bit_count() );
        else
            result = trace_primitive( lookup, tracer ? tracer : *this );

        // Insert a cache entry for the exact variable we're looking up and return.
        //
        cache.emplace( lookup, result );
#if VTIL_OPT_TRACE_VERBOSE
        // Log result.
        //
        log<CON_BRG>( "= %s\n", result );
#endif
        return result;
    }

    // Wrappers of trace and rtrace with cached basic tracer.
	//
	symbolic::expression cached_tracer::trace( const symbolic::variable& lookup, bool pack )
	{
		symbolic::expression&& result = trace_basic_cached( lookup );
		return pack ? symbolic::variable::pack_all( result ) : result;
	}
	symbolic::expression cached_tracer::rtrace( const symbolic::variable& lookup, bool pack )
	{
		symbolic::expression&& result = rtrace_primitive( lookup, *this );
		return pack ? symbolic::variable::pack_all( result ) : result;
	}
}