#pragma once
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