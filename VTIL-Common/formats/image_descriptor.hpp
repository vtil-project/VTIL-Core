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
#include <stdint.h>
#include <string>
#include <optional>
#include "../util/zip.hpp"
#include "../util/numeric_iterator.hpp"

namespace vtil
{
	// Generic section information.
	//
	struct section_descriptor
	{
		// Name of the section.
		//
		std::string name = {};

		// Characteristics of the section.
		//
		bool valid = false;
		bool read = false;
		bool write = false;
		bool execute = false;

		// Relative virtual address of the section and the lenght of the data at runtime.
		//
		uint64_t virtual_address = 0;
		size_t  virtual_size = 0;

		// Physical address of the section and the length of the data on disk.
		//
		uint64_t physical_address = 0;
		size_t  physical_size = 0;
	
		// Cast to bool redirects to ::valid.
		//
		explicit operator bool() const { return valid; }

		// Translates relative virtual address to physical address.
		//
		std::optional<uint64_t> translate( uint64_t rva ) const
		{
			if ( virtual_address <= rva && rva < ( virtual_address + virtual_size ) )
			{
				uint64_t offset = rva - physical_address;
				if ( offset < physical_size )
				{
					return offset + physical_address;
				}
			}
			return std::nullopt;
		}
	};

	// Generic image interface.
	//
	struct image_descriptor
	{
		// Declare the iterator type.
		//
		struct section_iterator_end_tag_t {};
		struct section_iterator
		{
			// Generic iterator typedefs.
			//
			using iterator_category = std::bidirectional_iterator_tag;
			using difference_type =   size_t;
			using value_type =        section_descriptor;
			using pointer =           section_descriptor*;
			using reference =         section_descriptor&;

			// Range of iteration and a reference to the original binary.
			//
			size_t at;
			size_t limit;
			const image_descriptor* binary;

			// Default constructor.
			//
			section_iterator( const image_descriptor* binary, size_t at ) :
				at( at ), limit( binary->get_section_count() ), binary( binary ) {}

			// Support bidirectional iteration.
			//
			section_iterator& operator++() { at++; return *this; }
			section_iterator& operator--() { at--; return *this; }

			// Equality check against another iterator.
			//
			bool operator==( const section_iterator& other ) const
			{ 
				return at == other.at && limit == other.limit;
			}
			bool operator!=( const section_iterator& other ) const
			{ 
				return at != other.at || limit != other.limit;
			}
			
			// Equality check against special end iterator.
			//
			bool operator==( section_iterator_end_tag_t ) const { return at == limit; }
			bool operator!=( section_iterator_end_tag_t ) const { return at != limit; }

			// Redirect dereferencing to the binary itself.
			//
			value_type operator*() { return binary->get_section( at ); }
			value_type operator*() const { return binary->get_section( at ); }
		};

		// Returns the number of sections in the binary.
		//
		virtual size_t get_section_count() const = 0;

		// Returns the details of the Nth section in the binary.
		//
		virtual section_descriptor get_section( size_t index ) const = 0;

		// Modifies the characteristics of the Nth section according to the information passed.
		//
		virtual void modify_section( size_t index, const section_descriptor& desc ) = 0;

		// Returns the next relative virtual address that'd the next section added using ::add_section would be assigned.
		//
		virtual uint64_t next_free_rva() const = 0;

		// Appends a new section to the binary. ::name/read/write/execute will be used, rest will be overwritten.
		//
		virtual void add_section( section_descriptor& in_out, const void* data, size_t size ) = 0;

		// Returns whether the address provided will be relocated or not.
		//
		virtual bool is_relocated( uint64_t rva ) const = 0;

		// Returns the image base.
		//
		virtual uint64_t get_image_base() const = 0;

		// Returns the image size and the raw byte array.
		//
		virtual size_t get_image_size() const = 0;
		virtual void* data() = 0;
		virtual const void* cdata() const = 0;

		// Retuns whether or not the image is valid.
		//
		virtual bool is_valid() const = 0;

		// Returns the section associated with the given relative virtual address.
		//
		std::pair<section_descriptor, size_t> rva_to_section( uint64_t rva ) const
		{
			for ( auto [scn, idx] : zip( *this, iindices() ) )
			{
				if ( scn.virtual_address <= rva && rva < ( scn.virtual_address + scn.virtual_size ) )
					return { scn, idx };
			}
			return {};
		}

		// Returns the data associated with the given relative virtual address.
		//
		template<typename T = void>
		T* rva_to_ptr( uint64_t rva )
		{
			auto [scn, _] = rva_to_section( rva );
			if ( !scn ) return nullptr;
			auto offset = scn.translate( rva );
			if ( !offset ) return nullptr;
			return ( T* ) ( ( uint8_t* ) data() + *offset );
		}
		template<typename T = void>
		const T* rva_to_ptr( uint64_t rva ) const
		{
			auto [scn, _] = rva_to_section( rva );
			if ( !scn ) return nullptr;
			auto offset = scn.translate( rva );
			if ( !offset ) return nullptr;
			return ( const T* ) ( ( const uint8_t* ) cdata() + *offset );
		}

		// Wrap get_section to make the interface iterable.
		//
		section_iterator begin() const { return { this, 0 }; }
		section_iterator_end_tag_t end() const { return {}; }
		section_descriptor operator[]( size_t n ) const { return get_section( n ); }

		// Cast to bool redirects to ::is_valid.
		//
		explicit operator bool() const { return is_valid(); }
	};
};