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
#include "register_view.hpp"
#include <vtil/math>
#include <vtil/amd64>

namespace vtil::arch
{
	// Basically an extended version of the register descriptor constructor
	// with the addition of an offset and a size value.
	//
	register_view::register_view( x86_reg base, uint8_t offset, uint8_t size ) : base( base ), size( size ), offset( offset ) { fassert( is_valid() ); }
	register_view::register_view( const std::string& base, uint8_t offset, uint8_t size ) : base( base ), size( size ), offset( offset ) { fassert( is_valid() ); }
	register_view::register_view( const register_desc& base, uint8_t offset, uint8_t size ) : base( base ), size( size ), offset( offset ) { fassert( is_valid() ); }

	// Basic comparison operators.
	//
	bool register_view::operator<( const register_view& o ) const 
	{ 
		// Try to sort based on base identifier first.
		//
		if ( base.identifier != o.base.identifier )
			return base.identifier < o.base.identifier;

		// If matching, check offset and size.
		//
		uint64_t mask_0 = math::mask( size, offset );
		uint64_t mask_1 = math::mask( o.size, o.offset );
		return mask_0 < mask_1;
	}
	bool register_view::operator==( const register_view& o ) const
	{
		return base.identifier == o.base.identifier && offset == o.offset && size == o.size;
	}
	bool register_view::operator!=( const register_view& o ) const { return !operator==( o ); };

	// Conversion to human-readable format.
	//
	std::string register_view::to_string( bool explicit_size ) const
	{
		if ( base.is_physical() )
		{
			if ( base.maps_to >= X86_REG_VCR0 )
				return lookup_control_register( base.maps_to )->identifier;

			x86_reg reg = amd64::remap( base.maps_to, offset, size );
			return amd64::name( reg );
		}

		std::string out = base.identifier;
		if ( explicit_size && size != 8 )
			out += format::suffix_map[ size ];
		if ( offset != 0 )
			out += "@" + std::to_string( offset );
		return out;
	}
};