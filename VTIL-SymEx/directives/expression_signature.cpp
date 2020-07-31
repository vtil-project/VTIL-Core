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
#include "expression_signature.hpp"

namespace vtil::symbolic
{
	// Declare number of bits used to save operator id.
	// -- Intellisense has a hard time bitscanning apparently (kills it across entire project) so yeah...
	//
#ifdef __INTELLISENSE__
	static constexpr bitcnt_t num_operator_bits = 6;
#else
	static constexpr bitcnt_t num_operator_bits = math::msb( ( uint64_t ) math::operator_id::max );
#endif

	// Declare shrinking factor, determines how many bits are conserved from grand-child nodes.
	//
	static constexpr bitcnt_t shrink_to = ( 64 - num_operator_bits ) / 2;

	// Extend from N bits into 64 bits.
	//
	template<bitcnt_t N>
	static constexpr uint64_t extend_u( uint64_t i )
	{
		constexpr bitcnt_t middle_original = 64 / 2;
		constexpr bitcnt_t middle_new =      N / 2;
		constexpr bitcnt_t shl_n =           middle_original - middle_new;
		return i << shl_n;
	}
	static constexpr uint64_t extend( math::operator_id o ) 
	{ 
		return extend_u<num_operator_bits>( ( uint64_t ) o ); 
	}

	// Shrink from 64 bits into N bits.
	//
	template<bitcnt_t N>
	static constexpr uint64_t shrink_u( uint64_t i )
	{
		constexpr bitcnt_t middle_original = 64 / 2;
		constexpr bitcnt_t middle_new =      N / 2;
		constexpr bitcnt_t shr_n =           middle_original - middle_new;
		constexpr bitcnt_t shl_n =           64 - shr_n;
		constexpr uint64_t mask =            math::fill( N );

		i |= i >> shl_n;
		i |= i << shl_n;
		return ( ( i >> shr_n ) | ( i << shl_n ) ) & mask;
	}

	// Rebalance I64 so that middle is LSB.
	//
	static constexpr uint64_t rebalance_u( uint64_t i ) { return ( i >> 32 ) | ( i << 32 ); }

	// Declare constructors.
	//
	expression_signature::expression_signature( const math::bit_vector& value )
	{
		// Write rebalanced integer.
		//
		signature[ 0 ] = 0;
		signature[ 1 ] = rebalance_u( value.known_one() );
		signature[ 2 ] = 0;

		// Write hash.
		//
		hash_value = { value.known_one() };
	}
	expression_signature::expression_signature( math::operator_id op, const expression_signature& rhs )
	{
		// Write [rhs, op, rhs].
		//
		signature[ 0 ] = rhs.shrink();
		signature[ 1 ] = extend( op );
		signature[ 2 ] = signature[ 0 ];

		// Write hash.
		//
		hash_value = make_hash( rhs.hash(), ( uint8_t ) op );
	}
	expression_signature::expression_signature( const expression_signature& lhs, math::operator_id op, const expression_signature& rhs )
	{
		// Skip if invalid operator.
		//
		if ( op >= math::operator_id::max )
		{
			signature.fill( 0 );
			return;
		}

		// Write [lhs, op, rhs].
		//
		signature[ 0 ] = lhs.shrink();
		signature[ 1 ] = extend( op );
		signature[ 2 ] = rhs.shrink();

		// Or both sides with each other if commutative.
		//
		bool is_commutative = math::descriptor_of( op ).is_commutative;
		if ( is_commutative )
			signature[ 2 ] = ( signature[ 0 ] |= signature[ 2 ] );

		// Write hash.
		//
		hash_value = combine_hash( 
			is_commutative ? combine_unordered_hash( lhs.hash(), rhs.hash() ) : combine_hash( lhs.hash(), rhs.hash() ),
			( uint8_t ) op
		);
	}

	// Shinks to a single 64-bit integer.
	//
	uint64_t expression_signature::shrink() const
	{
		return shrink_u<shrink_to>( signature[ 0 ] ) | signature[ 1 ] | ( shrink_u<shrink_to>( signature[ 2 ] ) << ( 64 - shrink_to ) );
	}
};
