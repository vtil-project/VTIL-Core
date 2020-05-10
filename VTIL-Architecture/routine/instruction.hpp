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
#include <vector>
#include <string>
#include <vtil/utility>
#include "../arch/instruction_set.hpp"

namespace vtil
{
	// Simple helper to create an immediate operand since vtil::operand( v, size ) gets redundant.
	//
	template<typename T> 
	static operand make_imm( T value ) { return operand( value, sizeof( T ) * 8 ); }

	// Type we use to describe virtual instruction pointer in.
	//
	using vip_t = uint64_t;
	static constexpr vip_t invalid_vip = -1;

	// This structure is used to describe instances of VTIL instructions in
	// the instruction stream.
	//
	struct instruction : reducable<instruction>
	{
		// Base instruction type.
		//
		const instruction_desc* base = nullptr;

		// List of operands.
		//
		std::vector<operand> operands;

		// Virtual instruction pointer that this instruction
		// originally was generated based on.
		//
		vip_t vip = invalid_vip;

		// The offset of current stack pointer from the last 
		// [MOV SP, <>] if applicable, or the beginning of 
		// the basic block and the index of the stack instance.
		//
		int64_t sp_offset = 0;
		uint32_t sp_index = 0;
		bool sp_reset = false;

		// Whether the instruction was explicitly declared volatile.
		//
		bool explicit_volatile = false;

		// Basic constructor, non-default constructor asserts the constructed
		// instruction is valid according to the instruction descriptor.
		//
		instruction() = default;
		instruction( const instruction_desc* base,
					 const std::vector<operand>& operands = {},
					 vip_t vip = invalid_vip,
					 bool explicit_volatile = false ) :
			base( base ), operands( operands ),
			vip( vip ), explicit_volatile( explicit_volatile )
		{
			fassert( is_valid() );
		}

		// Returns whether the instruction is valid or not.
		//
		bool is_valid() const;

		// Makes the instruction explicitly volatile.
		//
		auto& make_volatile() { explicit_volatile = true; return *this; }

		// Returns whether this instruction was directly translated
		// from a virtual machine instruction or not
		//
		bool is_pseudo() const { return vip == invalid_vip; }

		// Returns whether the instruction is volatile or not.
		//
		bool is_volatile() const { return explicit_volatile || base->is_volatile; }

		// Returns the access size of the instruction.
		//
		size_t access_size() const { return operands.empty() ? 0 : operands[ base->access_size_index ].size(); }

		// Returns the memory address this instruction references.
		//
		std::pair<register_desc, int64_t> get_mem_loc() const;

		// Checks whether the instruction reads from the given register or not, and
		// returns [operand index + 1] if a match is found and zero otherwise.
		//
		int reads_from( const register_desc& rw ) const;

		// Checks whether the instruction reads from the given register or not, and
		// returns [operand index + 1] if a match is found and zero otherwise.
		//
		int writes_to( const register_desc& rw ) const;

		// Checks whether the instruction reads from the given register or not, and
		// returns [operand index + 1] if a match is found and zero otherwise.
		//
		int overwrites( const register_desc& rw ) const;

		// Conversion to human-readable format.
		//
		std::string to_string( bool pad_right = false ) const;

		// Declare reduction.
		//
		auto reduce() { return reference_as_tuple( vip, sp_offset, operands, base->name, sp_index, sp_reset, explicit_volatile ); }

		// TODO: Remove me.
		//  Let modern compilers know that we use these operators as is,
		//  implementation considering all candidates would be preferred
		//  but since not all of our target compilers implement complete
		//  ISO C++20, we have to go with this "patch".
		//
		using reducable::operator<;
		using reducable::operator==;
		using reducable::operator!=;
	};
};
