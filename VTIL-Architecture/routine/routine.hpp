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
#include <mutex>
#include <type_traits>
#include <functional>
#include <vtil/utility>
#include "instruction.hpp"
#include "call_convention.hpp"

namespace vtil
{
	// Forward declaration of basic block.
	//
	struct basic_block;

	// Descriptor for any routine that is being translated.
	//
	struct routine
	{
		// This structure cannot be copied without a call to ::clone().
		//
		routine() = default;
		routine( const routine& ) = delete;
		routine& operator=( const routine& ) = delete;

		// Mutex guarding the whole structure, more information on thread-safety can be found at basic_block.hpp.
		//
		mutable critical_section mutex;

		// Cache of explored blocks, mapping virtual instruction pointer to the basic block structure.
		//
		std::map<vip_t, basic_block*> explored_blocks;

		// Reference to the first block, entry point.
		// - Can be accessed without acquiring the mutex as it will be assigned strictly once.
		//
		basic_block* entry_point = nullptr;

		// Last local identifier used for an internal register.
		//
		std::atomic<uint64_t> last_internal_id = { 0 };

		// Calling convention of the routine.
		//
		call_convention routine_convention = preserve_all_convention;

		// Calling convention of a non-specialized VXCALL.
		//
		call_convention subroutine_convention = default_call_convention;

		// Convention of specialized calls, maps the vip of the VXCALL instruction onto the convention used.
		//
		std::map<vip_t, call_convention> spec_subroutine_conventions;

		// Misc. stats.
		//
		std::atomic<size_t> local_opt_count = { 0 };

		// Multivariate runtime context.
		//
		mutable multivariate context = {};

		// Helpers for the allocation of unique internal registers.
		//
		register_desc alloc( bitcnt_t size )
		{
			return { register_internal, last_internal_id++, size };
		}
		template<typename... params>
		auto alloc( bitcnt_t size_0, params... size_n )
		{
			return std::make_tuple( alloc( size_0 ), alloc( size_n )... );
		}

		// Invokes the enumerator passed for each basic block this routine contains.
		//
		void for_each( const std::function<void( basic_block* )>& enumerator )
		{
			std::lock_guard _g( mutex );
			for ( auto& [vip, block] : explored_blocks )
				enumerator( block );
		}

		// Gets the calling convention for the given VIP (that resolves into VXCALL.
		//
		call_convention get_cconv( vip_t vip ) const
		{
			std::lock_guard _g( mutex );
			if ( auto it = spec_subroutine_conventions.find( vip ); it != spec_subroutine_conventions.end() )
				return it->second;
			return subroutine_convention;
		}

		// Sets the calling convention for the given VIP (that resolves into VXCALL.
		//
		void set_cconv( vip_t vip, const call_convention& cc )
		{
			std::lock_guard _g( mutex );
			spec_subroutine_conventions[ vip ] = cc;
		}

		// Routine structures free all basic blocks they own upon their destruction.
		//
		~routine();

		// Clones the routine and it's every block.
		//
		routine* clone() const;
	};
};