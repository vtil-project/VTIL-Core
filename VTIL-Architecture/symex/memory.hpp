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
#include <list>
#include "pointer.hpp"
#include "variable.hpp"
#include "../arch/register_desc.hpp"

namespace vtil::symbolic
{
	struct memory
	{
		// Common typedefs.
		//
		using store_entry =              std::pair<pointer, expression::reference>;
		using store_type =               std::list<store_entry>;

		// The memory state.
		//
		bool relaxed_aliasing;
		store_type value_map;

		// Default constructor, optionally takes a boolean to indicate relaxed aliasing.
		//
		memory( bool relaxed_aliasing = false )
			: relaxed_aliasing( relaxed_aliasing ) {}

		// Default copy/move.
		//
		memory( memory&& ) = default;
		memory( const memory& ) = default;
		memory& operator=( memory&& ) = default;
		memory& operator=( const memory& ) = default;

		// Wrap around the store type.
		//
		auto begin() { return value_map.begin(); }
		auto end() { return value_map.end(); }
		auto begin() const { return value_map.cbegin(); }
		auto end() const { return value_map.cend(); }
		size_t size() const { return value_map.size(); }
		void reset() { value_map.clear(); }

		// Returns the mask of known/unknown bits of the given region, if alias failure occurs returns nullopt.
		// 
		std::optional<uint64_t> known_mask( const pointer& ptr, bitcnt_t size ) const;
		std::optional<uint64_t> unknown_mask( const pointer& ptr, bitcnt_t size ) const;

		// Reads N bits from the given pointer, returns null reference if alias failure occurs.
		// - Will output the mask of bits contained in the state into contains if it does not fail.
		//
		expression::reference read( const pointer& ptr, bitcnt_t size, const il_const_iterator& reference_iterator = symbolic::free_form_iterator, uint64_t* contains = nullptr ) const;

		// Writes the given value to the pointer, returns null reference if alias failure occurs.
		//
		optional_reference<expression::reference> write( const pointer& ptr, deferred_value<expression::reference> value, bitcnt_t size );
		optional_reference<expression::reference> write( const pointer& ptr, expression::reference value ) { return write( ptr, value, value.size() ); }
	};
};