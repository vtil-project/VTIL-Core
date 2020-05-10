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
    symbolic::expression cached_tracer::trace_basic_cached( const variable& lookup )
    {
        // Declare a predicate for the search of the variable in the cache.
        //
        using cache_entry = std::pair<variable, symbolic::expression::reference>;
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
                return self.pointer == other.pointer &&
                    self.size >= other.size;
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

        // Search the map, if we find a matching entry return after resizing.
        // - We search starting from the small entries to avoid the cost of
        //   shrinking where it's feasable.
        //
        auto it = std::find_if( cache.begin(), cache.end(), predicate );
        if ( it != cache.end() )
            return symbolic::expression{ *it->second }.resize( lookup.bit_count() );

        // Trace the variable, insert into the cache.
        //
        symbolic::expression result = optimizer::trace( lookup, false );
        cache.emplace( lookup, result );
        return result;
    }

    // Wrappers of trace and rtrace with cached basic tracer.
	//
	symbolic::expression cached_tracer::trace( const variable& lookup, bool pack )
	{
		symbolic::expression&& result = trace_basic_cached( lookup );
		return pack ? variable::pack_all( result ) : result;
	}
	symbolic::expression cached_tracer::rtrace( const variable& lookup, bool pack )
	{
		symbolic::expression&& result = rtrace_primitive( lookup, [ & ] ( auto v )
		{
			return trace_basic_cached( v );
		} );
		return pack ? variable::pack_all( result ) : result;
	}
}