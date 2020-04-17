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
#include "control_registers.hpp"

namespace vtil::arch
{
	// Global list of control registers and the mutex protecting it.
	//
	static std::mutex control_register_list_mutex = {};
	static std::vector<control_register_desc> control_register_list = {};

	// Looks up the descriptor for the given control register.
	//
	std::optional<control_register_desc> lookup_control_register( x86_reg reg )
	{
		std::lock_guard g( control_register_list_mutex );

		// Calculate the index and lookup the global list
		//
		size_t index = reg - X86_REG_VCR0;
		if ( control_register_list.size() <= index )
			return std::nullopt;
		return control_register_list[ index ];
	}

	// Creates a new control register based on the descriptor and returns the
	// x86_reg value that it is mapped to.
	//
	x86_reg create_control_register( const control_register_desc& descriptor )
	{
		std::lock_guard g( control_register_list_mutex );

		// Calculate the index we will place this register at
		// push it up the list and then return the equivalent
		// x86_reg value
		//
		size_t index = control_register_list.size();
		control_register_list.push_back( descriptor );
		return X86_REG_VCR( index );
	}
};