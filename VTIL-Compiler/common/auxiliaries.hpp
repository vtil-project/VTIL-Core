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
#include <vtil/symex>
#include <vtil/arch>

namespace vtil::optimizer::aux
{
	struct branch_analysis_flags
	{
		uint32_t cross_block    : 1 = false;
		uint32_t pack           : 1 = false;
		uint32_t resolve_opaque : 1 = false;
	};

	// Simple structure describing branch details.
	//
	struct branch_info
	{
		// If jump to real:
		//
		bool is_vm_exit = false;
		
		// If jcc:
		//
		bool is_jcc = false;
		symbolic::expression::reference cc;

		// Possible destination expressions:
		//
		std::vector<symbolic::expression::reference> destinations;
	};

	// Helper to check if the expression given is block-local.
	//
	bool is_local( const symbolic::expression& ex );

	// Helper to check if the current value stored in the variable is used by the routine.
	//
	bool is_used( const symbolic::variable& var, bool rec, tracer* tracer );

	// Helper to check if the given symbolic variable's value is preserved upto [dst].
	//
	bool is_alive( const symbolic::variable& var, const il_const_iterator& dst, bool rec, tracer* tracer );

	// Revives the value of the given variable to be used by the point specified.
	//
	register_desc revive_register( const symbolic::variable& var, const il_iterator& it );

	// Extracts the details of the branch taken at the end of the block where possible.
	// - CC&1 responsibility is left to the caller.
	//
	branch_info analyze_branch( const basic_block* blk, tracer* tracer, branch_analysis_flags flags );

	// Checks if an instruction is a semantic NOP.
	//
	bool is_semantic_nop( const instruction& ins );

	// Removes all NOPs,.
	//
	size_t remove_nops( basic_block* blk, bool semantic_nops = true, bool volatile_nops = false );
	size_t remove_nops( routine* rtn, bool semantic_nops = true, bool volatile_nops = false );
}