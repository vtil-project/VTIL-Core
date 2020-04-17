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
#include "directive.hpp"

namespace vtil::symbolic
{
	// Constructor for directive representing the result of an unary operator.
	//
	directive::directive( math::operator_id _op, const directive& e1 )
	{
		// If directive is unpacking, handle it.
		//
		if ( e1.op == unpack_dir )
		{
			lhs = { _op, *e1.lhs }; rhs = { _op, *e1.rhs };
			op = unpack_dir;
		}
		// Otherwise describe as is.
		//
		else
		{
			rhs = e1;
			op = _op;
		}
	}

	// Constructor for directive representing the result of a binary operator.
	//
	directive::directive( const directive& e1, math::operator_id _op, const directive& e2 )
	{
		// If any of the directives are unpacking, handle it.
		//
		if ( e1.op == unpack_dir && e2.op == unpack_dir )
		{
			lhs = { *e1.lhs, _op, *e2.lhs }; rhs = { *e1.rhs, _op, *e2.rhs };
			op = unpack_dir;
		}
		else if ( e2.op == unpack_dir )
		{
			lhs = { e1, _op, *e2.lhs }; rhs = { e1, _op, *e2.rhs };
			op = unpack_dir;
		}
		else if ( e1.op == unpack_dir )
		{
			lhs = { *e1.lhs, _op, e2 }; rhs = { *e1.rhs, _op, e2 };
			op = unpack_dir;
		}
		// Otherwise describe as is.
		//
		else
		{
			lhs = e1; rhs = e2;
			op = _op;
		}
	}

	// Converts to human-readable format.
	//
	std::string directive::to_string() const
	{
		// Handle constants.
		//
		if ( op == math::operator_id::invalid )
			return id ? id : format::hex( i64 );

		// Handle custom operators.
		//
		if ( op == simplify_dir ) return "!" + rhs->to_string();
		if ( op == unpack_dir )   return "{" + lhs->to_string() + ", " + rhs->to_string() + "}";
		if ( op == iff_dir )      return lhs->to_string() + " ? " + rhs->to_string();
		if ( op == or_dir )       return lhs->to_string() + " <=> " + rhs->to_string();

		// Redirect to operator descriptor.
		//
		return math::descriptor_of( op )->to_string( lhs ? lhs->to_string() : "", rhs->to_string() );
	}

	// Simple equivalence check.
	//
	bool directive::equals( const directive& o ) const
	{
		// Operators must match.
		//
		if ( op != o.op )
			return false;

		// If variable, check the identifier and constant.
		//
		if ( op == math::operator_id::invalid )
			return o.op == math::operator_id::invalid && id == o.id && u64 == o.u64;

		// Handle custom operators.
		//
		if ( op == simplify_dir )
			return rhs->equals( *o.rhs );
		if ( op == unpack_dir || op == iff_dir || op == or_dir )
			return lhs->equals( *o.lhs ) && rhs->equals( *o.rhs );

		// Resolve operator descriptor, if unary, just compare right hand side.
		//
		const math::operator_desc* desc = math::descriptor_of( op );
		if ( desc->operand_count == 1 )
			return rhs->equals( *o.rhs );

		// If both sides match, return true.
		//
		if ( lhs->equals( *o.lhs ) && rhs->equals( *o.rhs ) )
			return true;

		// If not, check in reverse as well if commutative and return the final result.
		//
		return desc->is_commutative && rhs->equals( *o.lhs ) && lhs->equals( *o.rhs );
	}
};