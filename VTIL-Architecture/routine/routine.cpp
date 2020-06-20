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
#include "routine.hpp"
#include "basic_block.hpp"

namespace vtil
{
	// Routine structures free all basic blocks they own upon their destruction.
	//
	routine::~routine()
	{
		for ( auto [vip, block] : explored_blocks )
			delete block;
	}

	// Clones the routine and it's every block.
	//
	routine* routine::clone() const
	{
		routine* copy = new routine{};

		// Acquire the routine mutex.
		//
		std::lock_guard g{ this->mutex };

		// Copy the context data.
		//
		copy->context = this->context;

		// Copy calling conventions.
		//
		copy->routine_convention = this->routine_convention;
		copy->subroutine_convention = this->subroutine_convention;
		copy->spec_subroutine_conventions = this->spec_subroutine_conventions;

		// Copy internally tracked stats.
		//
		copy->local_opt_count = this->local_opt_count.load();
		copy->last_internal_id = this->last_internal_id.load();

		// Create a recursive clone helper and call into it with entry point.
		//
		const std::function<basic_block*(const basic_block*)> reference_block = 
			[ & ] ( const basic_block* src ) -> basic_block*
		{
			// If already indexed, return as is.
			//
			basic_block*& index = copy->explored_blocks[ src->entry_vip ];
			if ( index ) return index;
			
			// Copy the block and fix it's references.
			//
			index = new basic_block{ *src };
			index->owner = copy;
			
			for ( basic_block*& next : index->next )
				next = reference_block( next );
			for ( basic_block*& prev : index->prev )
				prev = reference_block( prev );
			return index;
		};
		copy->entry_point = reference_block( this->entry_point );

		// Iterate each explored block to make sure we've covered all.
		//
		for ( auto& [vip, block] : this->explored_blocks )
			fassert( copy->explored_blocks[ vip ] == reference_block( block ) );

		// Return the copy.
		//
		return copy;
	}
};
