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
#include "serialization.hpp"
#include <algorithm>

#pragma warning(disable:4267)
namespace vtil
{
	using magic_t = uint32_t;
	static constexpr magic_t vtil_magic = 'LITV';

	// Serialization of VTIL blocks.
	//
	void serialize( std::ostream& out, const basic_block* in )
	{
		// Write rest of the properties as is.
		//
		serialize( out, in->entry_vip );
		serialize( out, in->sp_offset );
		serialize( out, in->sp_index );
		serialize( out, in->last_temporary_index );
		serialize( out, in->stream );

		// Write the entry VIP of each block reference instead of the pointer. 
		//
		serialize<clength_t>( out, in->prev.size() );
		std::transform( in->prev.begin(), in->prev.end(), std::ostream_iterator<vip_t>( out ), [ ] ( auto it ) { return it->entry_vip; } );
		serialize<clength_t>( out, in->next.size() );
		std::transform( in->next.begin(), in->next.end(), std::ostream_iterator<vip_t>( out ), [ ] ( auto it ) { return it->entry_vip; } );
	}
	void deserialize( std::istream& in, routine* rtn, basic_block*& blk )
	{
		// Create a new block, read basic properties and bind to the owner
		//
		blk = new basic_block;
		deserialize( in, blk->entry_vip );
		deserialize( in, blk->sp_offset );
		deserialize( in, blk->sp_index );
		deserialize( in, blk->last_temporary_index );
		deserialize( in, blk->stream );
		blk->owner = rtn;
		blk->owner->explored_blocks[ blk->entry_vip ] = blk;

		// Read referenced VIP's.
		//
		std::vector<vip_t> prev;
		std::vector<vip_t> next;
		deserialize( in, prev );
		deserialize( in, next );

		// Resolve each reference.
		//
		auto ref_resolve = [ &in, &rtn ] ( vip_t vip )
		{
			// Reference the cached instance.
			//
			basic_block*& blk = rtn->explored_blocks[ vip ];

			// Keep reading next block until referenced block is found,
			// once it is found break out of the loop and return the block.
			//
			while ( !blk )
			{
				basic_block* tmp;
				deserialize( in, rtn, tmp );
			}
			return blk;
		};
		std::transform( prev.begin(), prev.end(), std::back_inserter( blk->prev ), ref_resolve );
		std::transform( next.begin(), next.end(), std::back_inserter( blk->next ), ref_resolve );
	}

	// Serialization of VTIL routines.
	//
	void serialize( std::ostream& out, const routine* rtn )
	{
		// Write the magic.
		//
		serialize( out, vtil_magic );

		// Write the entry point VIP.
		//
		serialize( out, rtn->entry_point->entry_vip );

		// Write the number of blocks we will serialize.
		//
		serialize<clength_t>( out, rtn->explored_blocks.size() );

		// Dump all blocks in cached order.
		//
		for ( auto& pair : rtn->explored_blocks )
			serialize( out, pair.second );
	}
	routine* deserialize( std::istream& in, routine*& rtn )
	{
		// Read and validate the magic.
		//
		magic_t magic;
		deserialize( in, magic );
		if ( magic != vtil_magic )
			return nullptr;

		// Create a new routine.
		//
		rtn = new routine;

		// Read the entry point VIP.
		//
		vip_t entry_vip;
		deserialize( in, entry_vip );

		// Read the number of blocks serialized and invoke basic-block 
		// deserialization until number of blocks read matches.
		//
		clength_t num_blocks;
		deserialize( in, num_blocks );
		while ( rtn->explored_blocks.size() != num_blocks )
		{
			basic_block* tmp;
			deserialize( in, rtn, tmp );
		}

		// Assign the fetched entry point from cache and return.
		//
		rtn->entry_point = rtn->explored_blocks[ entry_vip ];
		fassert( rtn->entry_point );
		return rtn;
	}

	// Serialization of VTIL instructions.
	//
	static void serialize( std::ostream& out, const instruction& in )
	{
		// Write only the name of the instruction instead of the pointer.
		//
		serialize( out, in.base->name );

		// Write rest as is.
		//
		serialize( out, in.operands );
		serialize( out, in.vip );
		serialize( out, in.sp_offset );
		serialize( out, in.sp_index );
		serialize( out, in.sp_reset );
	}
	static void deserialize( std::istream& in, instruction& out )
	{
		// Find the instruction by its name and write the pointer to the matched instance.
		//
		std::string name;
		deserialize( in, name );
		out.base = std::find( std::begin( instruction_list ), std::end( instruction_list ), name );
		fassert( out.base != std::end( instruction_list ) );

		// Read rest as is and validate.
		//
		deserialize( in, out.operands );
		deserialize( in, out.vip );
		deserialize( in, out.sp_offset );
		deserialize( in, out.sp_index );
		deserialize( in, out.sp_reset );
		fassert( out.is_valid() );
	}
};
#pragma warning(default:4267)