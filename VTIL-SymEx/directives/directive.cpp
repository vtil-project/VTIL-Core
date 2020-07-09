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
#include "directive.hpp"

namespace vtil::symbolic::directive
{
	// Constructor for directive representing the result of an unary operator.
	//
	instance::instance( math::operator_id op, const instance& e1 ) : rhs( e1 ), op( op ) {}

	// Constructor for directive representing the result of a binary operator.
	//
	instance::instance( const instance& e1, math::operator_id op, const instance& e2 ) : lhs( e1 ), rhs( e2 ), op( op ) {}

	// Enumerates each unique variable.
	//
	void instance::enum_variables( const std::function<void( const instance& )>& fn, std::unordered_set<const char*>* s ) const
	{
		std::unordered_set<const char*> tmp;
		if ( !s ) s = &tmp;

		if ( lhs ) lhs->enum_variables( fn, s );
		if ( rhs ) rhs->enum_variables( fn, s );
		else if ( !is_constant() )
		{
			if ( s->find( id ) == s->end() )
				s->insert( id ), fn( *this );
		}
	}

	// Converts to human-readable format.
	//
	std::string instance::to_string() const
	{
		// Handle constants.
		//
		if ( op == math::operator_id::invalid )
			return id ? id : format::hex( get<true>().value() );

		// Handle expression operators.
		//
		if ( auto desc = math::descriptor_of( op ) )
			return desc->to_string( lhs ? lhs->to_string() : "", rhs->to_string() );

		// Handle directive operators.
		//
		return directive_op_desc{ op }.to_string( lhs ? lhs->to_string() : "", rhs->to_string() );
	}

	// Simple equivalence check.
	//
	bool instance::equals( const instance& o ) const
	{
		// Operators must match.
		//
		if ( op != o.op )
			return false;

		// If variable, check the identifier and constant.
		//
		if ( op == math::operator_id::invalid )
			return o.op == math::operator_id::invalid && id == o.id && value.get().value_or( 0 ) == o.value.get().value_or( 0 );

		// Strict operand checking (Commutative rule not applied).
		//
		if ( !rhs ) return !o.rhs;
		else if ( !o.rhs || !rhs->equals( *o.rhs ) ) return false;
		if ( !lhs ) return !o.lhs;
		else if ( !o.lhs || !lhs->equals( *o.lhs ) ) return false;
		return true;
	}
};