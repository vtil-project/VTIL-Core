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
#include "translation.hpp"

namespace vtil
{
	// Translation with a cache lookup to avoid dupliate calculations.
	//
	struct batch_translator
	{
		// Block we are translating into.
		//
		basic_block* block;

		// The expression cache.
		//
		std::unordered_map<symbolic::expression::reference, operand, 
			               symbolic::expression::reference::hasher, 
			               symbolic::expression::reference::if_identical> translation_cache;
		
		// Constructed by binding to a block.
		//
		batch_translator( basic_block* block ) : block( block ) {}

		// operator<< is used to translate expressions.
		//
		operand operator<<( const symbolic::expression::reference& exp )
		{
			// If integer, return as is.
			//
			if ( exp->is_constant() ) return { *exp->get(), exp->size() };
			
			operand& op = translation_cache[ exp ];
			if ( !op.is_valid() )
			{
				op = translate_expression(
					exp,
					block,
					[ & ] ( auto& exp, auto* block ) { return *this << exp; }
				);
			}
			fassert( exp.size() == op.bit_count() );
			return op;
		}
	};
};