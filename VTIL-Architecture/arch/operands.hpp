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
			bitcnt_t bit_count;

			// Replicate default constructor, skipping the reducable base.
			//
			constexpr immediate_t() : u64( 0 ), bit_count( 0 ) {}
			constexpr immediate_t( uint64_t u64, bitcnt_t bit_count )
				: u64( u64 ), bit_count( bit_count ) {}

			// Declare reduction.
			//
			REDUCE_TO( u64, bit_count );
		};

		// Descriptor of this operand.
		//
		std::variant<immediate_t, register_t> descriptor = {};

		// Default constructor / move / copy.
		//
		constexpr operand()  {}
		constexpr operand( operand&& ) = default;
		constexpr operand( const operand& ) = default;
		constexpr operand& operator=( operand&& ) = default;
		constexpr operand& operator=( const operand& ) = default;

		// Construct by register descriptor.
		//		
		template<typename T> requires( !Integral<std::decay_t<T>> && !std::is_same_v<std::decay_t<T>, operand> )
		constexpr operand( T&& reg ) 
			: descriptor( register_cast<std::decay_t<T>>{}( std::forward<T>( reg ) ) ) {}

		// Construct by immediate optionally followed by the number of bits.
		//
		template<Integral T>
		constexpr operand( T value, bitcnt_t bit_count = sizeof( T ) * 8 ) 
			: descriptor( immediate_t{ ( uint64_t ) math::imm_extend( value ), bit_count } ) {}

		// Wrappers around std::get.
		//
		constexpr immediate_t& imm() { return std::get<immediate_t>( descriptor ); }
		constexpr const immediate_t& imm() const { return std::get<immediate_t>( descriptor ); }
		constexpr register_t& reg() { return std::get<register_t>( descriptor ); }
		constexpr const register_t& reg() const { return std::get<register_t>( descriptor ); }

		// Getter for the operand size (byte variant rounds up).
		//
		constexpr size_t size() const { return ( bit_count() + 7 ) / 8; }
		constexpr bitcnt_t bit_count() const { return is_register() ? reg().bit_count : imm().bit_count; }

		// Conversion to human-readable format.
		//
		std::string to_string() const { return is_register() ? reg().to_string() : format::hex( imm().i64 ); }

		// Simple helpers to determine the type of operand.
		//
		constexpr bool is_register() const { return std::holds_alternative<register_t>( descriptor ); }
		constexpr bool is_immediate() const { return std::holds_alternative<immediate_t>( descriptor ) && imm().bit_count != 0; }
		constexpr bool is_valid() const
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
		REDUCE_TO( descriptor );
	};
	#pragma pack(pop)
};