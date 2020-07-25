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
#include "pointer.hpp"
#include <numeric>
#include <vtil/math>
#include "../arch/register_desc.hpp"
#include "variable.hpp"

namespace vtil::symbolic
{
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

	// Construct from symbolic expression.
	//
	pointer::pointer( const expression::reference& _base ) : base( _base.simplify() )
	{
		// Determine pointer flags.
		//
		base->evaluate( [ & ] ( const unique_identifier& uid )
		{
			// If variable is a register that is a restricted base pointer:
			//
			if ( auto base = get_restricted_base( uid.get<variable>() ) )
			{
				// Set flags.
				//
				flags |= base->flags;
			}

			// Return dummy result.
			//
			return 0ull;
		} );

		// Initialize x values.
		//
		xvalues = base->xvalues();
	}

	// Simple pointer offseting.
	//
	pointer pointer::operator+( int64_t dst ) const
	{
		pointer copy = *this;
		copy.base = std::move( copy.base ) + dst;
		std::transform(
			std::begin( xvalues ), std::end( xvalues ),
			std::begin( copy.xvalues ),
			[ = ] ( auto v ) { return v + dst; }
		);
		return copy;
	}

	// Calculates the distance between two pointers as an optional constant.
	//
	std::optional<int64_t> pointer::operator-( const pointer& o ) const
	{
		int64_t delta = xvalues[ 0 ] - o.xvalues[ 0 ];
		for ( size_t n = 1; n < xvalues.size(); n++ )
			if ( ( xvalues[ n ] - o.xvalues[ n ] ) != delta )
				return std::nullopt;
		return ( base - o.base ).get<true>();
	}

	// Checks whether the two pointers can overlap in terms of real destination, 
	// note that it will consider [rsp+C1] and [rsp+C2] "overlapping" so you will
	// need to check the displacement with the variable sizes considered if you 
	// are checking "is overlapping" instead.
	//
	bool pointer::can_overlap( const pointer& o ) const
	{
		return ( ( flags & o.flags ) == flags   ) ||
			   ( ( flags & o.flags ) == o.flags );
	}

	// Same as can_overlap but will return false if flags do not overlap.
	//
	bool pointer::can_overlap_s( const pointer& o ) const
	{
		return ( ( flags & o.flags ) == flags   ) &&
			   ( ( flags & o.flags ) == o.flags );
	}
};