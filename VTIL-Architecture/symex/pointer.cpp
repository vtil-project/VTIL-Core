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
#include "pointer.hpp"
#include <numeric>
#include <vtil/math>
#include "../arch/register_desc.hpp"
#include "variable.hpp"

namespace vtil::symbolic
{
	// List of pointer bases we consider to be restricted, can be expanded by user
	// but defaults to image base and stack pointer.
	//
	std::set<register_desc> pointer::restricted_bases = { REG_SP, REG_IMGBASE };

	// Given a variable or an expression, checks if it is basing from a 
	// known restricted pointer, if so returns the register it's based off of.
	//
	static std::optional<register_desc> get_restricted_base( const variable& var )
	{
		// If variable is not a register, return null.
		//
		if ( !var.is_register() )
			return std::nullopt;

		// Search for it in the restricted base list, if found return.
		//
		const register_desc& reg = var.reg();
		return pointer::restricted_bases.contains( reg ) ? std::optional{ reg } : std::nullopt;
	}
	static std::optional<register_desc> get_restricted_base( const expression& e )
	{
		// If expression is a variable, check as is:
		//
		if ( e.is_variable() )
			return get_restricted_base( e.uid.get<variable>() );

		// Else apply a custom logic per operation:
		//
		switch ( e.op )
		{
			case math::operator_id::add:
			{
				auto lhs = get_restricted_base( *e.lhs );
				auto rhs = get_restricted_base( *e.rhs );
				if ( !rhs ) return lhs;
				if ( !lhs ) return rhs;
				return lhs == rhs ? rhs : std::nullopt;
			}
			case math::operator_id::bitwise_or:
			case math::operator_id::bitwise_and:
				if ( auto lhs = get_restricted_base( *e.lhs ) )
					return lhs;
				else
					return get_restricted_base( *e.rhs );
			case math::operator_id::subtract:
				return get_restricted_base( *e.lhs );
			case math::operator_id::value_if:
				return get_restricted_base( *e.rhs );
			default:
				return {};
		}
	}

	// Magic value substituting for invalid xpointers.
	//
	static constexpr uint64_t invalid_xpointer = make_crandom();

	// List of keys used for xpointer generation.
	//
	static constexpr std::array xpointer_keys = make_crandom_n<VTIL_SYM_PTR_XPTR_KEYS>( 1 );

	// Construct from symbolic expression.
	//
	pointer::pointer( expression&& _base ) : base( std::move( _base ) )
	{
		// Determine pointer strength and the flags.
		//
		strenght = +1;
		base.evaluate( [ & ] ( const unique_identifier& uid )
		{
			// If variable is a register that is a restricted base pointer:
			//
			if ( auto base = get_restricted_base( uid.get<variable>() ) )
			{
				// Set flags.
				//
				flags |= base->flags;
			}
			// Contains an unknown variable so make weak pointer.
			//
			else
			{
				strenght = -1;
			}

			// Return dummy result.
			//
			return 0ull;
		} );

		// Initialize X-Pointers.
		//
		for ( auto [xptr, key] : zip( xpointer, xpointer_keys ) )
		{
			xptr = base.get( [ k = uint64_t( key ) ]( const unique_identifier& uid )
			{
				// Hash the identifier of the value with the current key and mask it.
				//
				const variable& var = uid.get<variable>();
				if ( var.is_register() )
				{
					const variable::register_t& reg = var.reg();
					uint64_t pseudo_pointer = make_hash( reg.flags, reg.bit_offset, reg.local_id, k ).as64();
					return pseudo_pointer & math::fill( reg.bit_count );
				}
				else
				{
					const variable::memory_t& mem = var.mem();
					uint64_t pseudo_pointer = combine_hash( var.hash(), hash_t{ k } ).as64();
					return pseudo_pointer & math::fill( mem.bit_count );
				}
			} ).value_or( invalid_xpointer );
		}
	}

	// Simple pointer offseting.
	//
	pointer pointer::operator+( int64_t dst ) const
	{
		pointer copy = *this;
		copy.base = std::move( copy.base ).decay() + dst;
		std::transform(
			std::begin( xpointer ), std::end( xpointer ),
			std::begin( copy.xpointer ),
			[ = ] ( auto v ) { return v + dst; }
		);
		return copy;
	}

	// Calculates the distance between two pointers as an optional constant.
	//
	std::optional<int64_t> pointer::operator-( const pointer& o ) const
	{
		int64_t delta = xpointer[ 0 ] - o.xpointer[ 0 ];
		for ( size_t n = 1; n < xpointer.size(); n++ )
			if ( ( xpointer[ n ] - o.xpointer[ n ] ) != delta )
				return std::nullopt;

#if VTIL_SYM_PTR_SAFE_DISP
		return ( pointer.decay() - o.pointer.decay() ).get<true>();
#else
		return delta;
#endif
	}

	// Checks whether the two pointers can overlap in terms of real destination, 
	// note that it will consider [rsp+C1] and [rsp+C2] "overlapping" so you will
	// need to check the displacement with the variable sizes considered if you 
	// are checking "is overlapping" instead.
	//
	bool pointer::can_overlap( const pointer& o ) const
	{
		return ( ( flags & o.flags ) == flags ) ||
			   ( ( flags & o.flags ) == o.flags );
	}

	// Same as can_overlap but will return false if flags do not overlap.
	//
	bool pointer::can_overlap_s( const pointer& o ) const
	{
		return ( ( flags & o.flags ) == flags ) &&
			   ( ( flags & o.flags ) == o.flags );
	}
};