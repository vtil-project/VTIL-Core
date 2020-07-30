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
#include <vtil/utility>
#include <unordered_map>
#include "variable.hpp"
#include "../arch/register_desc.hpp"

namespace vtil::symbolic
{
	struct context
	{
		// Common typedefs.
		//
		struct segmented_value
		{
			symbolic::expression::reference linear_store[ 64 ] = { nullptr };
			uint64_t bitmap = 0;
		};
		using store_type = std::unordered_map<register_desc::weak_id, segmented_value>;

		// The register state.
		//
		store_type value_map;

		// Default copy/move/construct.
		//
		context() = default;
		context( context&& ) = default;
		context( const context& ) = default;
		context& operator=( context&& ) = default;
		context& operator=( const context& ) = default;

		// Wrap around the store type.
		//
		auto begin() { return value_map.begin(); }
		auto end() { return value_map.end(); }
		auto begin() const { return value_map.cbegin(); }
		auto end() const { return value_map.cend(); }
		size_t size() const { return value_map.size(); }
		void reset() { value_map.clear(); }

		// Returns the absolute mask of known/unknown bits of the given register.
		//
		uint64_t known_mask( const register_desc& desc ) const;
		uint64_t unknown_mask( const register_desc& desc ) const;

		// Reads the value of the given region described by the register desc.
		// - Will output the mask of bits contained in the state into contains.
		//
		expression::reference read( const register_desc& desc, const il_const_iterator& reference_iterator = symbolic::free_form_iterator, uint64_t* contains = nullptr ) const;

		// Writes the given value to the region described by the register desc.
		//
		void write( const register_desc& desc, expression::reference value );
	};
};