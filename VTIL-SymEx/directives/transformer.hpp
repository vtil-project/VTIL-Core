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
#include "directive.hpp"
#include "fast_matcher.hpp"
#include "../expressions/expression.hpp"

namespace vtil::symbolic
{
	using expression_filter_t = std::function<bool( expression::reference& ref )>;

	// Translates the given directive into an expression (of size given) using the symbol table.
	// - If speculative flag is set, it will either return a dummy reference if the expression could be built,
	//   or a null reference if it would fail.
	//
	expression::reference translate( const directive::symbol_table_t& sym,
									 const directive::instance::reference& dir,
									 bitcnt_t bit_cnt,
									 bool speculative_condition,
									 int64_t max_depth );

	// Attempts to transform the expression in form A to form B as indicated by the directives, 
	// and returns the first instance that matches query.
	//
	expression::reference transform( const expression::reference& exp, 
									 const directive::instance::reference& from, const directive::instance::reference& to,
									 const expression_filter_t& filter,
									 int64_t max_depth );
};