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
#include <algorithm>
#include <vtil/io>
#include <vtil/utility>
#include <vtil/arch>
#include <vtil/symex>
#include "variable.hpp"

// [Configuration]
// Determine whether we should log the details of the variable tracing process.
//
#ifndef VTIL_OPT_TRACE_VERBOSE
	#define VTIL_OPT_TRACE_VERBOSE 0
#endif

namespace vtil::optimizer
{
    // Some convenience typedefs.
    //
    using path_history_t =      std::map<std::pair<const basic_block*, const basic_block*>, uint32_t>;
    using trace_function_t =    std::function<symbolic::expression( const variable& lookup )>;

    // Traces a variable across the basic block it belongs to and generates a symbolic expression 
    // that describes it's value at the bound point. Will invoke the passed tracer for any additional 
    // tracing it requires.
    //
    symbolic::expression trace_primitive( variable lookup, const trace_function_t& tracer );
    
    // Traces a variable across the entire routine and generates a symbolic expression that describes 
    // it's value at the bound point. Will invoke the passed tracer for any additional tracing it requires. 
    // Takes an optional path history used internally to recurse in a controlled fashion.
    //
    symbolic::expression rtrace_primitive( const variable& lookup, const trace_function_t& tracer, const path_history_t& history = {} );

    // Simple wrappers around primitive trace and rtrace with optional packing of the variables.
    //
    symbolic::expression trace( const variable& lookup, bool pack = true );
    symbolic::expression rtrace( const variable& lookup, bool pack = true );
};