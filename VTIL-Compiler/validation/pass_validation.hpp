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
#include <vtil/arch>
#include <vtil/common>
#include <functional>

namespace vtil::optimizer::validation
{
	// Default register state of the virtual machine, rest will be zero'd out.
	//
	static constexpr std::pair<const register_desc&, uint64_t> default_register_state[] = {
		{ REG_SP,      0x7F000008 },
		{ REG_IMGBASE, 0x0 },
		{ REG_FLAGS,   0x0 }
	};

	// Series of actions that can be obeserved outside of the virtual machine to verify behaviour.
	//
	struct memory_write
	{
		uint64_t address;
		uint64_t value;
	};

	struct memory_read
	{
		uint64_t address;
		uint64_t fake_value;
		bitcnt_t size;
	};

	struct external_call
	{
		uint64_t address;
		std::vector<uint64_t> parameters;
		std::vector<uint64_t> fake_result;
	};

	struct vm_exit
	{
		std::map<register_desc, uint64_t> register_state;
	};

	using observable_action = std::variant<memory_write, memory_read, external_call, vm_exit>;

	// Helper routine used to compare routine behaviour against expected behaviour.
	//
	bool verify_symbolic( const routine* rtn, const std::vector<uint64_t>& parameters, const std::vector<observable_action>& action_log );
};