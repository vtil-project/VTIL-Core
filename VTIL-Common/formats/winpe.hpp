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
#include <vector>
#include "image_descriptor.hpp"

namespace vtil
{
	// Describes a 64/32 bit Microsoft Portable Executable Image.
	//
	struct pe_image : image_descriptor
	{
		// Construct by raw byte array.
		//
		std::vector<uint8_t> raw_bytes;
		pe_image( const std::vector<uint8_t>& raw_bytes = {} ) : raw_bytes( raw_bytes ) {}
		
		// Default move/copy.
		//
		pe_image( pe_image&& ) = default;
		pe_image( const pe_image& ) = default;
		pe_image& operator=( pe_image&& ) = default;
		pe_image& operator=( const pe_image& ) = default;

		// Implement the interface requirements:
		//
		virtual size_t get_section_count() const override;
		virtual section_descriptor get_section( size_t index ) const override;
		virtual void modify_section( size_t index, const section_descriptor& desc ) override;
		virtual uint64_t next_free_rva() const override;
		virtual void add_section( section_descriptor& in_out, const void* data, size_t size ) override;
		virtual bool is_relocated( uint64_t rva ) const override;
		virtual uint64_t get_image_base() const override;
		virtual size_t get_image_size() const override { return raw_bytes.size(); }
		virtual void* data()  override { return raw_bytes.data(); }
		virtual const void* cdata() const override { return raw_bytes.data(); }
		virtual bool is_valid() const override;

		// Helpers used to declare the functions.
		//
		bool is_pe64() const;
		uint64_t get_alignment_mask() const;
	};
};