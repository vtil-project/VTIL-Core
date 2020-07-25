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
#include <vtil/math>
#include <vtil/utility>
#include <vtil/io>
#include <array>

namespace vtil::symbolic
{
	// This class allows O(1) approximation of tree-matching by storing a 
	// compressed signature.
	//
	struct expression_signature : reducable<expression_signature>
	{
		// Signature itself.
		//
		std::array<uint64_t, 3> signature;

		// Signature hash.
		//
		hash_t hash_value;
		
		// Declare constructors.
		//
		expression_signature() {}
		expression_signature( const math::bit_vector& value );
		expression_signature( math::operator_id op, const expression_signature& rhs );
		expression_signature( const expression_signature& lhs, math::operator_id op, const expression_signature& rhs );

		// Default copy/move.
		//
		expression_signature( expression_signature&& ) = default;
		expression_signature( const expression_signature& ) = default;
		expression_signature& operator=( expression_signature&& ) = default;
		expression_signature& operator=( const expression_signature& ) = default;
		
		// Shinks to a single 64-bit integer.
		//
		uint64_t shrink() const;
		
		// Checks if RHS can match into LHS.
		//
		bool can_match( const expression_signature& o ) const
		{
			for ( auto [a, b] : zip( signature, o.signature ) )
				if ( ( a & b ) != b )
					return false;
			return true;
		}

		// Custom hasher.
		//
		hash_t hash() const { return hash_value; }
		
		// Declare reduction.
		//
		REDUCE_TO( signature );
	};
};