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
#include <memory>
#include <vtil/arch>

namespace vtil::optimizer::validation
{
	// Generic test interface.
	//
	struct unit_test
	{
		// Returns a copy of the original routine.
		//
		virtual std::unique_ptr<routine> generate() const = 0;
		
		// Validates whether the optimized copy is behaving as expected.
		// - Notes on implementation:
		//   - The prefix [/**/] should be added to any line which does not exist in the original routine.
		//   - The prefix [/**/ //] should be added to any line which exists in the original routine but was omitted.
		//
		virtual bool validate( const routine* rtn ) const = 0;

		// Overloads operator() for easy invocation. Should be called with a lambda / optimizer_pass,
		// generates the routine, passes through the optimizer and runs the validation [N=16] times.
		//
		template<typename callable>
		bool operator()( const callable& pass, size_t N = 16 ) const
		{
			// Generate and optimize the routine.
			//
			auto rtn = generate();
			pass( rtn.get() );
			
			// Validate the behaviour, fail if invalid.
			//
			for ( size_t i = 0; i < N; i++ )
				if ( !validate( rtn.get() ) ) 
					return false;
			
			// Signal success.
			//
			return true;
		}
	};
};