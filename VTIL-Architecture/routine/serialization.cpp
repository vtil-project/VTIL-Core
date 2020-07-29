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
#include "serialization.hpp"
#include <algorithm>
#include <stdexcept>

#pragma warning(disable:4267)
namespace vtil
{
#pragma pack(push, 1)
	struct file_header
	{
		uint32_t magic_1 = 'LITV';
		architecture_identifier arch_id;
		uint8_t zero_pad = 0;				// Intentionally left zero to make sure non-binary streams fail.
		uint16_t magic_2 = 0xDEAD;
	};
	static_assert( sizeof( file_header ) == 8, "Invalid file header size." );
#pragma pack(pop)

	// Serialization of VTIL calling conventions.
	//
	void serialize( std::ostream& out, const call_convention& in )
	{
		serialize( out, in.volatile_registers );
		serialize( out, in.param_registers );
		serialize( out, in.retval_registers );
		serialize( out, in.frame_register );
		serialize( out, in.shadow_space );
		serialize( out, in.purge_stack );
	}
	void deserialize( std::istream& in, call_convention& out )
	{
		deserialize( in, out.volatile_registers );
		deserialize( in, out.param_registers );
		deserialize( in, out.retval_registers );
		deserialize( in, out.frame_register );
		deserialize( in, out.shadow_space );
		deserialize( in, out.purge_stack );
	}

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
		serialize( out, *in );

		// Write the entry VIP of each block reference instead of the pointer. 
		//
		std::vector<vip_t> prev;
		std::vector<vip_t> next;
		auto ref_make = [ ] ( auto blk ) { return blk->entry_vip; };
		std::transform( in->prev.begin(), in->prev.end(), std::back_inserter( prev ), ref_make );
		std::transform( in->next.begin(), in->next.end(), std::back_inserter( next ), ref_make );
		serialize( out, prev );
		serialize( out, next );
	}
	void deserialize( std::istream& in, routine* rtn, basic_block*& blk )
	{
		// Create a new block, read basic properties and bind to the owner
		//
		vip_t vip;
		deserialize( in, vip );
		blk = new basic_block( rtn, vip );
		deserialize( in, blk->sp_offset );
		deserialize( in, blk->sp_index );
		deserialize( in, blk->last_temporary_index );
		std::vector<instruction> list;
		deserialize( in, list );
		blk->assign( list.begin(), list.end() );
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
		// Write the file header.
		//
		serialize( out, file_header{ .arch_id = rtn->arch_id } );

		// Write the entry point VIP.
		//
		serialize( out, rtn->entry_point->entry_vip );

		// Write the call conventions used.
		//
		serialize( out, rtn->routine_convention );
		serialize( out, rtn->subroutine_convention );
		serialize<clength_t>( out, rtn->spec_subroutine_conventions.size() );
		for ( auto& [k, v] : rtn->spec_subroutine_conventions )
		{
			serialize( out, k );
			serialize( out, v );
		}

		// Write the number of blocks we will serialize.
		//
		serialize<clength_t>( out, rtn->explored_blocks.size() );

		// Dump all blocks in cached order.
		//
		for ( auto& pair : rtn->explored_blocks )
			serialize( out, pair.second );
	}
	void deserialize( std::istream& in, routine*& rtn )
	{
		// Read and validate the file header.
		//
		file_header hdr;
		deserialize( in, hdr );
		if ( hdr.magic_1 != file_header{}.magic_1 ||
			 hdr.zero_pad != file_header{}.zero_pad ||
			 hdr.magic_2 != file_header{}.magic_2 )
			throw std::runtime_error( "Invalid VTIL header." );

		// Create a new routine.
		//
		rtn = new routine( hdr.arch_id );

		// Read the entry point VIP.
		//
		vip_t entry_vip;
		deserialize( in, entry_vip );

		// Read the call conventions used.
		//
		deserialize( in, rtn->routine_convention );
		deserialize( in, rtn->subroutine_convention );

		clength_t num_convs;
		deserialize( in, num_convs );
		while ( rtn->spec_subroutine_conventions.size() != num_convs )
		{
			vip_t k; call_convention v;
			deserialize( in, k ); deserialize( in, v );
			rtn->spec_subroutine_conventions[ k ] = v;
		}

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
		if ( !rtn->entry_point )
			throw std::runtime_error( "Failed resolving entry point." );

		// Determine last internal id.
		//
		uint64_t last_internal_id = 0;
		for ( auto& [v, block] : rtn->explored_blocks )
		{
			for ( auto& ins : *block )
			{
				for ( auto& op : ins.operands )
				{
					if ( op.is_register() && op.reg().is_internal() )
					{
						last_internal_id = std::max( 
							last_internal_id, 
							op.reg().local_id + 1 
						);
					}
				}
			}
		}
		rtn->last_internal_id = last_internal_id;

		// Flush paths.
		//
		rtn->flush_paths();
	}

	// Serialization of VTIL instructions.
	//
	void serialize( std::ostream& out, const instruction& in )
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
	void deserialize( std::istream& in, instruction& out )
	{
		// Find the instruction by its name and write the pointer to the matched instance.
		//
		std::string name;
		deserialize( in, name );

		out.base = nullptr;
		for ( auto ins : get_instruction_list() )
		{
			if ( ins->name == name )
			{
				out.base = ins;
				break;
			}
		}
		
		if ( !out.base )
			throw std::runtime_error( "Failed resolving instruction." );

		// Read rest as is and validate.
		//
		deserialize( in, out.operands );
		deserialize( in, out.vip );
		deserialize( in, out.sp_offset );
		deserialize( in, out.sp_index );
		deserialize( in, out.sp_reset );
		if( !out.is_valid() )
			throw std::runtime_error( "Resolved invalid instruction." );
	}

	// Serialization of VTIL operands.
	//
	void serialize( std::ostream& out, const operand& in )
	{
		// Write type index.
		//
		serialize<clength_t>( out, in.descriptor.index() );
		
		// Write the variant.
		//
		if ( in.descriptor.index() == 0 ) 
			return serialize( out, std::get<operand::immediate_t>( in.descriptor ) );
		if ( in.descriptor.index() == 1 ) 
			return serialize( out, std::get<operand::register_t>( in.descriptor ) );
		unreachable();
	}
	void deserialize( std::istream& in, operand& out )
	{
		// Read type index.
		//
		clength_t index;
		deserialize( in, index );

		// Try to read the variant.
		//
		if ( index == 0 )
		{
			operand::immediate_t value;
			deserialize( in, value );
			out.descriptor = value;
		}
		else if( index == 1 )
		{
			operand::register_t value;
			deserialize( in, value );
			out.descriptor = value;
		}
		else
		{
			throw std::runtime_error( "Resolved invalid operand." );
		}
	}
};
#pragma warning(default:4267)