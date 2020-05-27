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
#include <vtil/arch>

namespace vtil::optimizer
{
	// Declares a generic pass interface that any optimization pass implements.
	// - Passes should be always default constructable.
	//
	struct pass_interface
	{
		// Passes a single basic block through the optimizer, xblock will be set to true
		// if cross-block exploration is allowed.
		//
		virtual size_t pass( basic_block* blk, bool xblock = false ) = 0;

		// Passes every block through the optimizer with block refrences freely explorable,
		// returns the number of instances where this optimization was applied.
		//
		virtual size_t xpass( routine* rtn ) 
		{ 
			size_t n = 0; 
			rtn->for_each( [ & ] ( auto* blk ) { n += pass( blk, true ); } ); 
			return n; 
		}
	};

	// Passes through each optimizer provided and returns the total number of optimizations applied.
	//
	template<typename... Tx>
	struct combine_pass;
	template<typename T>
	struct combine_pass<T> : T {};
	template<typename T1, typename... Tx>
	struct combine_pass<T1, Tx...> : pass_interface
	{
		T1 t1 = {};
		combine_pass<Tx...> t2 = {};
		size_t pass( basic_block* blk, bool xblock = false ) override { return t1.pass( blk, xblock ) + t2.pass( blk, xblock ); }
		size_t xpass( routine* rtn ) override { return t1.xpass( rtn ) + t2.xpass( rtn ); }
	};

	// Passes through each optimizer provided until the passes do not change the block.
	//
	template<typename... Tx>
	struct exhaust_pass : combine_pass<Tx...>
	{
		// Simple looping until pass returns 0.
		//
		size_t pass( basic_block* blk, bool xblock = false ) override 
		{ 
			size_t cnt = combine_pass<Tx...>::pass( blk, xblock );
			return cnt ? cnt + exhaust_pass::pass( blk, xblock ) : 0;
		}
		size_t xpass( routine* rtn ) override
		{
			size_t cnt = combine_pass<Tx...>::xpass( rtn );
			return cnt ? cnt + exhaust_pass::xpass( rtn ) : 0;
		}
	};
};