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
#include "../symex/variable.hpp"

// [Configuration]
// Determine whether we should log the details of the variable tracing process.
//
#ifndef VTIL_OPT_TRACE_VERBOSE
	#define VTIL_OPT_TRACE_VERBOSE 0
#endif

namespace vtil
{
	// Basic tracer implementation.
	//
	struct tracer
	{
		bool recursive_flag = false;

		// Traces a variable across the basic block it belongs to and generates a symbolic expression 
		// that describes it's value at the bound point. The provided variable should not contain a 
		// pointer with out-of-block expressions.
		//
		virtual symbolic::expression trace( symbolic::variable lookup );

		// Traces a variable across the entire routine and tries to generates a symbolic expression
		// for it at the specified point of the block, limit determines the maximum number of blocks 
		// to trace backwards, any negative number implies infinite since it won't reach 0.
		//
		virtual symbolic::expression rtrace( symbolic::variable lookup, int64_t limit = -1 );

		// Wrappers around the functions above that return expressions with the registers packed.
		//
		symbolic::expression trace_p( symbolic::variable lookup ) { return symbolic::variable::pack_all( trace( std::move( lookup ) ) ); }
		symbolic::expression rtrace_p( symbolic::variable lookup, int64_t limit = -1 ) { return symbolic::variable::pack_all( rtrace( std::move( lookup ), limit ) ); }

		// Wrappers around trace(_p) and rtrace(_p) that can trace an entire expression.
		//
		symbolic::expression trace_exp( const symbolic::expression& exp );
		symbolic::expression rtrace_exp( const symbolic::expression& exp, int64_t limit = -1 );
		symbolic::expression trace_pexp( const symbolic::expression& exp ) { return symbolic::variable::pack_all( trace_exp( exp ) ); }
		symbolic::expression rtrace_pexp( const symbolic::expression& exp, int64_t limit = -1 ) { return symbolic::variable::pack_all( rtrace_exp( exp, limit ) ); }

		// Operator() wraps basic tracing with packing.
		//
		auto operator()( symbolic::variable lookup ) { return trace_p( std::move( lookup ) ); }
	};
};