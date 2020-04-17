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
#pragma once
#include <map>
#include <atomic>
#include <mutex>
#include <tuple>
#include <type_traits>
#include "instruction.hpp"

namespace vtil
{
	// Forward declaration of basic block.
	//
	struct basic_block;

	// Descriptor for any routine that is being translated.
	//
	struct routine
	{
		// Mutex guarding the whole structure, if a member is 
		// not explicitly marked, this mutex should be acquired
		// before accesing it.
		//
		std::mutex mutex;

		// Index of the last temporary register used.
		//
		std::atomic<int32_t> temporary_index_counter = -1;

		// Cache of explored blocks, mapping virtual instruction
		// pointer to the basic block structure.
		//
		std::map<vip_t, basic_block*> explored_blocks;

		// Reference to the first block, entry point.
		// - Can be accessed without acquiring the mutex as it
		//   will be assigned strictly once.
		//
		basic_block* entry_point = nullptr;

		// Invokes the enumerator passed for each basic block 
		// this routine contains.
		//
		template<typename enumerator_function>
		void for_each( const enumerator_function& enumerator ) const
		{
			for ( auto& block : explored_blocks )
				enumerator( const_cast<basic_block*>(block.second) );
		}
	};
};