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
#include <string>
#include <vtil/math>
#include <vtil/utility>
#include <variant>
#include "register_desc.hpp"

namespace vtil
{
	// Operand structure either holds an immediate or a register.
	//
	#pragma pack(push, 4)
	struct operand : reducable<operand>
	{
		// If register type, we just need the register descriptor.
		//
		using register_t = register_desc;

		// If immediate type, we need the immediate itself and
		// its size in number of bits.
		//
		struct immediate_t : reducable<immediate_t>
		{
			// Immediate value stored.
			//
			union
			{
				int64_t i64;
				uint64_t u64;
			};

			// Number of bits it is expressed in.
			//
			bitcnt_t bit_count = 0;

			// Replicate default constructor, skipping the reducable base.
			//
			immediate_t() {}
			immediate_t( uint64_t u64, bitcnt_t bit_count )
				: u64( u64 ), bit_count( bit_count ) {}

			// Declare reduction.
			//
			auto reduce() { return reference_as_tuple( u64, bit_count ); }

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

		// Descriptor of this operand.
		//
		std::variant<immediate_t, register_t> descriptor = {};

		// Default constructor / move / copy.
		//
		operand()  {}
		operand( operand&& ) = default;
		operand( const operand& ) = default;
		operand& operator=( operand&& ) = default;
		operand& operator=( const operand& ) = default;

		// Construct by register descriptor.
		//		
		template<typename T, std::enable_if_t<!std::is_same_v<std::remove_cvref_t<T>, operand>, int> = 0>
		operand( T&& reg ) : descriptor( register_cast<std::remove_cvref_t<T>>{}( reg ) ) {}

		// Construct by immediate followed by the number of bits.
		//
		template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
		operand( T value, bitcnt_t bit_count ) : descriptor( immediate_t{ ( uint64_t ) math::imm_extend( value ), bit_count } ) {}

		// Wrappers around std::get.
		//
		immediate_t& imm() { return std::get<immediate_t>( descriptor ); }
		const immediate_t& imm() const { return std::get<immediate_t>( descriptor ); }
		register_t& reg() { return std::get<register_t>( descriptor ); }
		const register_t& reg() const { return std::get<register_t>( descriptor ); }

		// Getter for the operand size (rounded-up to bytes).
		//
		size_t size() const { return ( ( is_register() ? reg().bit_count : imm().bit_count ) + 7 ) / 8; }

		// Conversion to human-readable format.
		//
		std::string to_string() const { return is_register() ? reg().to_string() : format::hex( imm().i64 ); }

		// Simple helpers to determine the type of operand.
		//
		bool is_register() const { return std::holds_alternative<register_t>( descriptor ); }
		bool is_immediate() const { return std::holds_alternative<immediate_t>( descriptor ) && imm().bit_count != 0; }
		bool is_valid() const 
		{ 
			// If register:
			//
			if ( is_register() )
			{
				// Bit offset and bit count must be both byte-aligned
				// with the exception of bit count == 1 for boolean registers.
				//
				if ( reg().bit_count != 1 )
				{
					return !( reg().bit_offset & 7 ) &&
						   !( reg().bit_count & 7 );
				}
				return true;
			}

			// Otherwise must be a valid immediate.
			//
			return is_immediate(); 
		}

		// Declare reduction.
		//
		auto reduce() { return reference_as_tuple( descriptor ); }
	};
	#pragma pack(pop)
};