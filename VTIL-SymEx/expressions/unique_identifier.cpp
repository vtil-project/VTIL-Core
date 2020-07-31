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
#include "unique_identifier.hpp"

namespace vtil::symbolic
{
	// Conversion to human-readable format.
	// - Note: Will cache the return value in string_cast as lambda capture if non-const-qualified.
	//
	const std::string& unique_identifier::to_string() const
	{
		static const std::string null_name = "null";
		if ( !value )
			return null_name;
		if ( name_getter.index() == 1 )
			name_getter = std::get<1>( name_getter )( value );
		return std::get<0>( name_getter );
	}

	// Simple comparison operators.
	//
	bool unique_identifier::operator==( const unique_identifier& o ) const
	{
		// If hash mismatch, return false.
		//
		if ( hash_value != o.hash_value ) return false;

		// Check for null.
		//
		if ( !value ) return !o.value;
		if ( !o.value ) return false;

		// Assert internal equivalance.
		//
		return compare_value( *this, o ) == 0;
	}
	bool unique_identifier::operator<( const unique_identifier& o ) const
	{
		// Consider null side less.
		//
		if ( !value ) return o.value;
		if ( !o.value ) return false;

		// Compare by hash.
		//
		if ( hash_value != o.hash_value )
			return hash_value < o.hash_value;

		// Compare internals if equivalent hash.
		//
		return compare_value( *this, o ) < 0;
	}
};
