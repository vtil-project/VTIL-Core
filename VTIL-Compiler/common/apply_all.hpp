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
#include "interface.hpp"
#include "../optimizer/stack_pinning_pass.hpp"
#include "../optimizer/istack_ref_substitution_pass.hpp"
#include "../optimizer/bblock_extension_pass.hpp"
#include "../optimizer/stack_propagation_pass.hpp"
#include "../optimizer/dead_code_elimination_pass.hpp"
#include "../optimizer/fast_dead_code_elimination_pass.hpp"
#include "../optimizer/fast_propagation_pass.hpp"
#include "../optimizer/mov_propagation_pass.hpp"
#include "../optimizer/symbolic_rewrite_pass.hpp"
#include "../optimizer/branch_correction_pass.hpp"
#include "../optimizer/register_renaming_pass.hpp"

namespace vtil::optimizer
{
	// TODO: Add a wrapping validation pass.
	//

	// Fast local passes.
	//
	using fast_local_passes = nop_pass; /* exhaust_pass<
		//fast_local_dead_code_elimination_pass,
		//fast_reg_propagation_pass,
		//fast_mem_propagation_pass,
		zero_pass<//fast_local_dead_code_elimination_pass>
	>;*/

	// Exhaustive propagation pass.
	//
	using collective_propagation_pass = exhaust_pass<
		stack_propagation_pass,
		local_pass<mov_propagation_pass>,
		local_pass<dead_code_elimination_pass>,
		mov_propagation_pass,
		register_renaming_pass,
		dead_code_elimination_pass,
		conditional_pass<
			branch_correction_pass,
			conditional_pass<
				bblock_extension_pass,
				symbolic_rewrite_pass<true>
			>
		>
	>;

	// Cross optimization pass.
	//
	using core_local_propagation_pass = combine_pass<
		local_pass<stack_propagation_pass>,
		local_pass<dead_code_elimination_pass>,
		local_pass<mov_propagation_pass>,
		local_pass<register_renaming_pass>,
		local_pass<dead_code_elimination_pass>
	>;
	using collective_cross_pass = combine_pass<
		stack_pinning_pass,
		istack_ref_substitution_pass,
		bblock_extension_pass,
		core_local_propagation_pass,
		dead_code_elimination_pass,
		symbolic_rewrite_pass<true>,
		branch_correction_pass,
		collective_propagation_pass,
		symbolic_rewrite_pass<true>,
		core_local_propagation_pass,
		collective_propagation_pass,
		//fast_dead_code_elimination_pass,
		exhaust_pass<
			conditional_pass<
				symbolic_rewrite_pass<false>,
				exhaust_pass<
					//fast_local_passes,
					//fast_dead_code_elimination_pass,
					collective_propagation_pass
				>
			>
		>,
		stack_pinning_pass
	>;

	// Local optimization pass.
	//
	using collective_local_pass = combine_pass<
		stack_pinning_pass,
		istack_ref_substitution_pass,
		//fast_local_passes,
		stack_propagation_pass,
		symbolic_rewrite_pass<true>,
		exhaust_pass<
			//fast_local_passes,
			mov_propagation_pass,
			register_renaming_pass
		>
	>;

	// Combined optimization pass.
	//
	using collective_pass = specialize_pass<
		collective_local_pass,
		collective_cross_pass
	>;

	// Combined pass for each optimization.
	//
	static constexpr spawn_state<collective_pass> apply_all = {};
	static constexpr spawn_state<apply_each<profile_pass, collective_pass>> apply_all_profiled = {};
};