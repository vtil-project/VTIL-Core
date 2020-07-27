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

// Furthermore, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information                   |
// |-------------------------|------------------------------------------------|
// | Architecture/*          | https://github.com/aquynh/capstone/            |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#pragma once
#include "../util/type_helpers.hpp"

namespace vtil
{
	// Structure describing how a register maps to another register.
	//
	template<typename T>
	struct register_mapping
	{
		// Base register of full size, e.g. X86_REG_RAX.
		//
		T base_register = T( 0 );

		// Offset of the current register from the base register.
		//
		int8_t offset = 0;

		// Size of the current register in bytes.
		//
		int8_t size = 0;
	};

	// register =(*n)=> [base_register] @ unique{ offset, size }
	//
	template<typename T, T limit>
	struct register_map
	{
		static constexpr size_t max_entry_count = ( size_t ) limit;
		static constexpr size_t max_xref_count = 8;
		static constexpr size_t invalid_xref = ~0ull;

		// Type of entries provided in the constructor.
		//
		using linear_entry_t = std::pair<T, register_mapping<T>>;
		struct lookup_entry_t : register_mapping<T> 
		{ 
			// Only for the parent, xref list will be assigned a list of children.
			//
			size_t xrefs[ max_xref_count ] = { 0 };
			constexpr lookup_entry_t() 
			{
				for ( size_t& v : xrefs ) 
					v = invalid_xref;
			}
		};

		// Lookup table type, and conversion into it.
		//
		lookup_entry_t linear_entries[ max_entry_count ] = {};
		constexpr register_map( std::initializer_list<linear_entry_t> entries )
		{
			for ( auto&& [id, entry] : entries )
			{
				// Must be the only reference to it.
				//
				auto& entry_n = linear_entries[ ( size_t ) id ];
				fassert( entry_n.size == 0 );

				// Write base details.
				//
				entry_n.base_register = entry.base_register;
				entry_n.offset = entry.offset;
				entry_n.size = entry.size;
				
				// Add xref to base register.
				//
				bool xref_added = false;
				for ( auto& xref : linear_entries[ ( size_t ) entry.base_register ].xrefs )
				{
					if ( xref == invalid_xref )
					{
						xref = ( size_t ) id;
						xref_added = true;
						break;
					}
				}
				fassert( xref_added );
			}
		}

		// Gets the offset<0> and size<1> of the mapping for the given register.
		//
		constexpr register_mapping<T> resolve_mapping( uint32_t _reg ) const
		{
			// Try to find the register mapping, if successful return.
			//
			auto& entry = linear_entries[ _reg ];
			if ( entry.size )
				return entry;

			// Otherwise return default mapping after making sure it's valid.
			//
			return { T( _reg ), 0, 8 };
		}

		// Gets the base register for the given register.
		//
		constexpr T extend( uint32_t _reg ) const
		{
			return resolve_mapping( _reg ).base_register;
		}

		// Remaps the given register at given specifications.
		//
		constexpr T remap( uint32_t _reg, uint32_t offset, uint32_t size ) const
		{
			// Try to find the register mapping, if successful:
			//
			auto& entry = linear_entries[ _reg ];
			if ( entry.size )
			{
				// Get base register entry, enumerate xrefs.
				//
				auto& bentry = linear_entries[ _reg = ( uint32_t ) entry.base_register ];
				fassert( bentry.size );

				for ( size_t xref : bentry.xrefs )
				{
					if ( xref != invalid_xref )
					{
						auto& pentry = linear_entries[ ( size_t ) xref ];

						if ( pentry.base_register == entry.base_register &&
							 pentry.offset == offset &&
							 pentry.size == size )
						{
							return ( T ) xref;
						}
					}
				}
			}

			// If we fail to find, and we're strictly remapping to a full register, return as is.
			//
			fassert( offset == 0 );
			return ( T ) _reg;
		}

		// Checks whether the register is a generic register that is handled.
		//
		constexpr bool is_generic( uint32_t _reg ) const
		{
			return linear_entries[ _reg ].size != 0;
		}
	};
}
