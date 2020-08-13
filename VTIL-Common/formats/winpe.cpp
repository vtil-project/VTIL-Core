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
#include "winpe.hpp"
#include "../io/asserts.hpp"
#include <string.h>
#include "../math/bitwise.hpp"

namespace vtil
{
#pragma pack(push, 4)
	// Magic constants
	//
	static constexpr uint16_t DOS_HDR_MAGIC = 0x5A4D; // "MZ"
	static constexpr uint32_t NT_HDR_MAGIC = 0x00004550; // "PE\x0\x0"
	static constexpr uint16_t OPT_HDR32_MAGIC = 0x010B;
	static constexpr uint16_t OPT_HDR64_MAGIC = 0x020B;

	static constexpr size_t NUM_DATA_DIRECTORIES = 16;
	static constexpr size_t LEN_SECTION_NAME = 8;

	// File target machine
	//
	enum class machine_id : uint16_t
	{
		unknown = 0x0000,
		target_host = 0x0001, // Useful for indicating we want to interact with the host and not a WoW guest.
		i386 = 0x014C, // Intel 386.
		r3000 = 0x0162, // MIPS little-endian, 0x160 big-endian
		r4000 = 0x0166, // MIPS little-endian
		r10000 = 0x0168, // MIPS little-endian
		wcemipsv2 = 0x0169, // MIPS little-endian WCE v2
		alpha = 0x0184, // Alpha_AXP
		sh3 = 0x01A2, // SH3 little-endian
		sh3dsp = 0x01A3,
		sh3e = 0x01A4, // SH3E little-endian
		sh4 = 0x01A6, // SH4 little-endian
		sh5 = 0x01A8, // SH5
		arm = 0x01C0, // ARM Little-Endian
		thumb = 0x01C2, // ARM Thumb/Thumb-2 Little-Endian
		armnt = 0x01C4, // ARM Thumb-2 Little-Endian
		am33 = 0x01D3,
		powerpc = 0x01F0, // IBM PowerPC Little-Endian
		powerpcfp = 0x01F1,
		ia64 = 0x0200, // Intel 64
		mips16 = 0x0266, // MIPS
		alpha64 = 0x0284, // ALPHA64
		mipsfpu = 0x0366, // MIPS
		mipsfpu16 = 0x0466, // MIPS
		axp64 = 0x0284,
		tricore = 0x0520, // Infineon
		cef = 0x0CEF,
		ebc = 0x0EBC, // EFI Byte Code
		amd64 = 0x8664, // AMD64 (K8)
		m32r = 0x9041, // M32R little-endian
		arm64 = 0xAA64, // ARM64 Little-Endian
		cee = 0xC0EE,
	};

	// Subsystems
	//
	enum class subsystem_id : uint16_t
	{
		unknown = 0x0000, // Unknown subsystem.
		native = 0x0001, // Image doesn't require a subsystem.
		windows_gui = 0x0002, // Image runs in the Windows GUI subsystem.
		windows_cui = 0x0003, // Image runs in the Windows character subsystem
		os2_cui = 0x0005, // image runs in the OS/2 character subsystem.
		posix_cui = 0x0007, // image runs in the Posix character subsystem.
		native_windows = 0x0008, // image is a native Win9x driver.
		windows_ce_gui = 0x0009, // Image runs in the Windows CE subsystem.
		efi_application = 0x000A, //
		efi_boot_service_driver = 0x000B, //
		efi_runtime_driver = 0x000C, //
		efi_rom = 0x000D,
		xbox = 0x000E,
		windows_boot_application = 0x0010,
		xbox_code_catalog = 0x0011,
	};

	// Directory indices
	//
	enum directory_id
	{
		directory_entry_export = 0, // Export Directory
		directory_entry_import = 1, // Import Directory
		directory_entry_resource = 2, // Resource Directory
		directory_entry_exception = 3, // Exception Directory
		directory_entry_security = 4, // Security Directory
		directory_entry_basereloc = 5, // Base Relocation Table
		directory_entry_debug = 6, // Debug Directory
		directory_entry_copyright = 7, // (X86 usage)
		directory_entry_architecture = 7, // Architecture Specific Data
		directory_entry_globalptr = 8, // RVA of GP
		directory_entry_tls = 9, // TLS Directory
		directory_entry_load_config = 10, // Load Configuration Directory
		directory_entry_bound_import = 11, // Bound Import Directory in headers
		directory_entry_iat = 12, // Import Address Table
		directory_entry_delay_import = 13, // Delay Load Import Descriptors
		directory_entry_com_descriptor = 14, // COM Runtime descriptor
		directory_reserved0 = 15, // -
	};

	// File characteristics
	//
	union file_characteristics_t
	{
		uint16_t flags;
		struct
		{
			uint16_t relocs_stripped : 1; // Relocation info stripped from file.
			uint16_t executable : 1; // File is executable  (i.e. no unresolved external references).
			uint16_t lines_stripped : 1; // Line nunbers stripped from file.
			uint16_t local_symbols_stripped : 1; // Local symbols stripped from file.
			uint16_t aggressive_ws_trim : 1; // Aggressively trim working set
			uint16_t large_address_aware : 1; // App can handle >2gb addresses
			uint16_t _pad0 : 1;
			uint16_t bytes_reversed_lo : 1; // Bytes of machine word are reversed.
			uint16_t machine_32 : 1; // 32 bit word machine.
			uint16_t debug_stripped : 1; // Debugging info stripped from file in .DBG file
			uint16_t runnable_from_swap : 1; // If Image is on removable media, copy and run from the swap file.
			uint16_t net_run_from_swap : 1; // If Image is on Net, copy and run from the swap file.
			uint16_t system_file : 1; // System File.
			uint16_t dll_file : 1; // File is a DLL.
			uint16_t up_system_only : 1; // File should only be run on a UP machine
			uint16_t bytes_reversed_hi : 1; // Bytes of machine word are reversed.
		};
	};

	// DLL characteristics
	//
	union dll_characteristics_t
	{
		uint16_t flags;
		struct
		{
			uint16_t _pad0 : 5;
			uint16_t high_entropy_va : 1; // Image can handle a high entropy 64-bit virtual address space.
			uint16_t dynamic_base : 1; // DLL can move.
			uint16_t force_integrity : 1; // Code Integrity Image
			uint16_t nx_compat : 1; // Image is NX compatible
			uint16_t no_isolation : 1; // Image understands isolation and doesn't want it
			uint16_t no_seh : 1; // Image does not use SEH.  No SE handler may reside in this image
			uint16_t no_bind : 1; // Do not bind this image.
			uint16_t appcontainer : 1; // Image should execute in an AppContainer
			uint16_t wdm_driver : 1; // Driver uses WDM model
			uint16_t guard_cf : 1; // Image supports Control Flow Guard.
			uint16_t terminal_server_aware : 1;
		};
	};

	// Section characteristics
	//
	union section_characteristics_t
	{
		uint32_t flags;
		struct
		{
			uint32_t _pad0 : 5;
			uint32_t cnt_code : 1; // Section contains code.
			uint32_t cnt_init_data : 1; // Section contains initialized data.
			uint32_t cnt_uninit_data : 1; // Section contains uninitialized data.
			uint32_t _pad1 : 1;
			uint32_t lnk_info : 1; // Section contains comments or some other type of information.
			uint32_t _pad2 : 1;
			uint32_t lnk_remove : 1; // Section contents will not become part of image.
			uint32_t lnk_comdat : 1; // Section contents comdat.
			uint32_t _pad3 : 1;
			uint32_t no_defer_spec_exc : 1; // Reset speculative exceptions handling bits in the TLB entries for this section.
			uint32_t mem_far : 1;
			uint32_t _pad4 : 1;
			uint32_t mem_purgeable : 1;
			uint32_t mem_locked : 1;
			uint32_t mem_preload : 1;
			uint32_t alignment : 4; // Alignment calculated as: n ? 1 << ( n - 1 ) : 16 
			uint32_t lnk_nreloc_ovfl : 1; // Section contains extended relocations.
			uint32_t mem_discardable : 1; // Section can be discarded.
			uint32_t mem_not_cached : 1; // Section is not cachable.
			uint32_t mem_not_paged : 1; // Section is not pageable.
			uint32_t mem_shared : 1; // Section is shareable.
			uint32_t mem_execute : 1; // Section is executable.
			uint32_t mem_read : 1; // Section is readable.
			uint32_t mem_write : 1; // Section is writeable.
		};

		uint32_t get_alignment() const { return alignment ? 1 << ( alignment - 1 ) : 0x10; }
	};

	// NT versioning
	//
	union version_t
	{
		uint16_t identifier;
		struct
		{
			uint8_t major;
			uint8_t minor;
		};
	};

	union ex_version_t
	{
		uint32_t identifier;
		struct
		{
			uint16_t major;
			uint16_t minor;
		};
	};

	// File header
	//
	struct file_header_t
	{
		machine_id machine;
		uint16_t num_sections;
		uint32_t timedate_stamp;
		uint32_t ptr_symbols;
		uint32_t num_symbols;
		uint16_t size_optional_header;
		file_characteristics_t characteristics;
	};

	// Data directories
	//
	struct data_directory_t
	{
		uint32_t rva;
		uint32_t size;

		bool present() const { return size; }
	};

	struct data_directories_x86_t
	{
		union
		{
			struct
			{
				data_directory_t export_directory;
				data_directory_t import_directory;
				data_directory_t resource_directory;
				data_directory_t exception_directory;
				data_directory_t security_directory;
				data_directory_t basereloc_directory;
				data_directory_t debug_directory;
				data_directory_t copyright_directory;
				data_directory_t globalptr_directory;
				data_directory_t tls_directory;
				data_directory_t load_config_directory;
				data_directory_t bound_import_directory;
				data_directory_t iat_directory;
				data_directory_t delay_import_directory;
				data_directory_t com_descriptor_directory;
				data_directory_t _reserved0;
			};
			data_directory_t entries[ NUM_DATA_DIRECTORIES ];
		};
	};

	struct data_directories_x64_t
	{
		union
		{
			struct
			{
				data_directory_t export_directory;
				data_directory_t import_directory;
				data_directory_t resource_directory;
				data_directory_t exception_directory;
				data_directory_t security_directory;
				data_directory_t basereloc_directory;
				data_directory_t debug_directory;
				data_directory_t architecture_directory;
				data_directory_t globalptr_directory;
				data_directory_t tls_directory;
				data_directory_t load_config_directory;
				data_directory_t bound_import_directory;
				data_directory_t iat_directory;
				data_directory_t delay_import_directory;
				data_directory_t com_descriptor_directory;
				data_directory_t _reserved0;
			};
			data_directory_t entries[ NUM_DATA_DIRECTORIES ];
		};
	};

	template<bool x64>
	struct data_directories_t : std::conditional_t<x64, data_directories_x64_t, data_directories_x86_t> {};

	// Optional header
	//
	struct optional_header_x64_t
	{
		// Standard fields.
		uint16_t magic;
		version_t linker_version;

		uint32_t size_code;
		uint32_t size_init_data;
		uint32_t size_uninit_data;

		uint32_t entry_point;
		uint32_t base_of_code;

		// NT additional fields.
		uint64_t image_base;
		uint32_t section_alignment;
		uint32_t file_alignment;

		ex_version_t os_version;
		ex_version_t img_version;
		ex_version_t subsystem_version;
		uint32_t win32_version_value;

		uint32_t size_image;
		uint32_t size_headers;

		uint32_t checksum;
		subsystem_id subsystem;
		dll_characteristics_t characteristics;

		uint64_t size_stack_reserve;
		uint64_t size_stack_commit;
		uint64_t size_heap_reserve;
		uint64_t size_heap_commit;

		uint32_t ldr_flags;

		uint32_t num_data_directories;
		data_directories_x64_t data_directories;
	};

	struct optional_header_x86_t
	{
		// Standard fields.
		uint16_t magic;
		version_t linker_version;

		uint32_t size_code;
		uint32_t size_init_data;
		uint32_t size_uninit_data;

		uint32_t entry_point;
		uint32_t base_of_code;
		uint32_t base_of_data;

		// NT additional fields.
		uint32_t image_base;
		uint32_t section_alignment;
		uint32_t file_alignment;

		ex_version_t os_version;
		ex_version_t img_version;
		ex_version_t subsystem_version;
		uint32_t win32_version_value;

		uint32_t size_image;
		uint32_t size_headers;

		uint32_t checksum;
		subsystem_id subsystem;
		dll_characteristics_t characteristics;

		uint32_t size_stack_reserve;
		uint32_t size_stack_commit;
		uint32_t size_heap_reserve;
		uint32_t size_heap_commit;

		uint32_t ldr_flags;

		uint32_t num_data_directories;
		data_directories_x86_t data_directories;

		bool has_directory( directory_id id ) const { return has_directory( &data_directories.entries[ id ] ); }
		bool has_directory( const data_directory_t* dir ) const { return &data_directories.entries[ num_data_directories ] < dir && dir->present(); }
	};
	template<bool x64>
	struct optional_header_t : std::conditional_t<x64, optional_header_x64_t, optional_header_x86_t> {};

	// Section header
	//
	struct section_header_t
	{
		char name[ LEN_SECTION_NAME ];

		union
		{
			uint32_t physical_address;
			uint32_t virtual_size;
		};
		uint32_t virtual_address;

		uint32_t size_raw_data;
		uint32_t ptr_raw_data;

		uint32_t ptr_relocs;
		uint32_t ptr_line_numbers;
		uint16_t num_relocs;
		uint16_t num_line_numbers;

		section_characteristics_t characteristics;
	};

	// NT headers
	//
	template<bool x64>
	struct nt_headers_t
	{
		uint32_t signature;
		file_header_t file_header;
		optional_header_t<x64> optional_header;

		auto get_sections() { return ( section_header_t* ) ( ( char* ) &optional_header + file_header.size_optional_header ); }
		auto get_sections() const { return ( const section_header_t* ) ( ( char* ) &optional_header + file_header.size_optional_header ); }
		auto get_section( size_t n ) { return get_sections() + n; }
		auto get_section( size_t n ) const { return get_sections() + n; }
	};
	using nt_headers_x64_t = nt_headers_t<true>;
	using nt_headers_x86_t = nt_headers_t<false>;

	// DOS header
	//
	struct dos_header_t
	{
		uint16_t e_magic;
		uint16_t e_cblp;
		uint16_t e_cp;
		uint16_t e_crlc;
		uint16_t e_cparhdr;
		uint16_t e_minalloc;
		uint16_t e_maxalloc;
		uint16_t e_ss;
		uint16_t e_sp;
		uint16_t e_csum;
		uint16_t e_ip;
		uint16_t e_cs;
		uint16_t e_lfarlc;
		uint16_t e_ovno;
		uint16_t e_res[ 4 ];
		uint16_t e_oemid;
		uint16_t e_oeminfo;
		uint16_t e_res2[ 10 ];
		uint32_t e_lfanew;

		template<bool x64> auto get_nt_headers() { return ( nt_headers_t<x64>* ) ( ( char* ) this + e_lfanew ); }
		template<bool x64> auto get_nt_headers() const { return ( const nt_headers_t<x64>* ) ( ( char* ) this + e_lfanew ); }
	};

	enum reloc_type_id
	{
	rel_based_absolute = 0,
	rel_based_high = 1,
	rel_based_low = 2,
	rel_based_high_low = 3,
	rel_based_high_adj = 4,
	rel_based_ia64_imm64 = 9,
	rel_based_dir64 = 10,
	};

	struct reloc_entry_t
	{
		uint16_t offset : 12;
		uint16_t type : 4;
	};

	struct reloc_block_t
	{
		uint32_t base_rva;
		uint32_t size_block;
		reloc_entry_t entries[ 1 ];   // Variable length array

		auto get_next() { return ( reloc_block_t* ) ( ( char* ) this + this->size_block ); }
		auto get_next() const { return ( const reloc_block_t* ) ( ( char* ) this + this->size_block ); }
		size_t num_entries() const { return ( reloc_entry_t* ) get_next() - &entries[ 0 ]; }
	};

	struct reloc_directory_t
	{
		reloc_block_t first_block;
	};

#pragma pack(pop)

	// Helpers used to declare the functions.
	//
	bool pe_image::is_pe64() const
	{
		auto dos_header = ( const dos_header_t* ) cdata();
		return dos_header->get_nt_headers<true>()->optional_header.magic == OPT_HDR64_MAGIC;
	}
	uint64_t pe_image::get_alignment_mask() const
	{
		auto dos_header = ( const dos_header_t* ) cdata();
		auto sec_alignment = is_pe64()
			? dos_header->get_nt_headers<true>()->optional_header.section_alignment
			: dos_header->get_nt_headers<false>()->optional_header.section_alignment;
		auto file_alignment = is_pe64()
			? dos_header->get_nt_headers<true>()->optional_header.file_alignment
			: dos_header->get_nt_headers<false>()->optional_header.file_alignment;

		return std::max( { file_alignment, file_alignment, 0x1000u } ) - 1;
	}

	// Implement the interface requirements:
	//
	size_t pe_image::get_section_count() const
	{
		// Get the section count from file header.
		//
		auto dos_header = ( const dos_header_t* ) cdata();
		return dos_header->get_nt_headers<true>()->file_header.num_sections;
	}

	section_descriptor pe_image::get_section( size_t index ) const
	{
		// Get the NT headers.
		//
		auto dos_header = ( const dos_header_t* ) cdata();
		auto nt_headers = dos_header->get_nt_headers<true>();

		// Return invalid descriptor if out-of-boundaries.
		//
		if ( nt_headers->file_header.num_sections <= index )
			return {};

		// Fill section descriptor and return.
		//
		auto scn_header = nt_headers->get_section( index );
		return {
			.name = { scn_header->name, scn_header->name + ( scn_header->name[ LEN_SECTION_NAME - 1 ] ? LEN_SECTION_NAME : strlen( scn_header->name ) ) },
			.valid = true,
			.read = ( bool ) scn_header->characteristics.mem_read,
			.write = ( bool ) scn_header->characteristics.mem_write,
			.execute = ( bool ) scn_header->characteristics.mem_execute,
			.virtual_address = scn_header->virtual_address,
			.virtual_size = scn_header->virtual_size,
			.physical_address = scn_header->ptr_raw_data,
			.physical_size = scn_header->size_raw_data
		};
	}

	void pe_image::modify_section( size_t index, const section_descriptor& desc )
	{
		// Get the NT headers.
		//
		auto dos_header = ( dos_header_t* ) cdata();
		auto nt_headers = dos_header->get_nt_headers<true>();

		// Fill section descriptor and return.
		//
		auto scn_header = nt_headers->get_section( index );
		memset( scn_header->name, 0, LEN_SECTION_NAME );
		memcpy( scn_header->name, desc.name.data(), std::min( desc.name.length(), LEN_SECTION_NAME ) );
		scn_header->characteristics.mem_read = desc.read;
		scn_header->characteristics.mem_write = desc.write;
		scn_header->characteristics.mem_execute = desc.execute;
	}

	uint64_t pe_image::next_free_rva() const
	{
		// Get the NT headers.
		//
		auto dos_header = ( const dos_header_t* ) cdata();
		auto nt_headers = dos_header->get_nt_headers<true>();

		// Iterate each section:
		//
		uint32_t rva_high = 0;
		uint32_t raw_low = 0;
		for ( size_t i = 0; i < nt_headers->file_header.num_sections; i++ )
		{
			// Reference section and calculate min-maxes.
			//
			auto scn = nt_headers->get_section( i );
			rva_high = std::max( scn->virtual_address + std::max( scn->virtual_size, scn->size_raw_data ), rva_high );
			raw_low = std::max( scn->ptr_raw_data, raw_low );
		}

		// Make sure there is space for another section.
		//
		uint32_t size_headers = is_pe64()
			? dos_header->get_nt_headers<true>()->optional_header.size_headers
			: dos_header->get_nt_headers<false>()->optional_header.size_headers;
		if ( raw_low <= ( sizeof( section_header_t ) + size_headers ) )
			return 0;

		// Page align rva high and calculate where we place the next section.
		//
		uint64_t alignment = get_alignment_mask();
		return ( rva_high + alignment ) & ~alignment;
	}

	uint64_t pe_image::get_image_base() const
	{
		// Get the image base from optional header.
		//
		auto dos_header = ( const dos_header_t* ) cdata();
		if ( is_pe64() )
			return dos_header->get_nt_headers<true>()->optional_header.image_base;
		else
			return dos_header->get_nt_headers<false>()->optional_header.image_base;
	}

	bool pe_image::is_valid() const
	{
		// Get image boundaries and the dos header.
		//
		const void* data = cdata();
		const void* data_limit = ( char* ) cdata() + get_image_size();
		auto dos_header = ( const dos_header_t* ) cdata();
		
		// Validate DOS header.
		//
		if ( dos_header->e_magic != DOS_HDR_MAGIC ) 
			return false;

		// Validate image size.
		//
		if ( ( ( const char* ) data + dos_header->e_lfanew + std::min( sizeof( nt_headers_x64_t ), sizeof( nt_headers_x86_t ) ) ) > data_limit )
			return false;

		// Validate NT Magic.
		//
		auto nt_header = dos_header->get_nt_headers<true>();
		if ( nt_header->signature != NT_HDR_MAGIC )
			return false;

		// Validat optional header magic.
		//
		if ( nt_header->optional_header.magic != OPT_HDR32_MAGIC &&
			 nt_header->optional_header.magic != OPT_HDR64_MAGIC )
			return false;
		
		// TODO: Validate more data...
		//
		return true;
	}

	void pe_image::add_section( section_descriptor& in_out, const void* data, size_t size )
	{
		uint64_t rva_sec = this->next_free_rva();
		uint64_t alignment = get_alignment_mask();
		size_t aligned_size = ( ( size + alignment ) & ~alignment );

		// Resize the raw image and copy the bytes.
		//
		size_t img_original_size = raw_bytes.size();
		raw_bytes.resize( img_original_size + aligned_size );
		memcpy( raw_bytes.data() + img_original_size, data, size );

		// Add the byte count into NT headers.
		//
		if ( is_pe64() )
		{
			auto& opt_header = ( ( dos_header_t* ) this->data() )->get_nt_headers<true>()->optional_header;
			opt_header.size_code += math::narrow_cast<uint32_t>( aligned_size );
			opt_header.size_image += math::narrow_cast<uint32_t>( aligned_size );
			opt_header.size_headers += ( uint32_t ) sizeof( section_header_t );
		}
		else
		{
			auto& opt_header = ( ( dos_header_t* ) this->data() )->get_nt_headers<false>()->optional_header;
			opt_header.size_code += math::narrow_cast<uint32_t>( aligned_size );
			opt_header.size_image += math::narrow_cast<uint32_t>( aligned_size );
			opt_header.size_headers += ( uint32_t ) sizeof( section_header_t );
		}

		// Append a section and write the characteristics.
		//
		auto nt_hdrs = ( ( dos_header_t* ) this->data() )->get_nt_headers<true>();
		size_t index = nt_hdrs->file_header.num_sections++;
		auto scn = nt_hdrs->get_section( index );
		memset( scn, 0, sizeof( section_header_t ) );
		modify_section( index, in_out );

		// Append location data and return.
		//
		in_out.virtual_address =  scn->virtual_address =  math::narrow_cast<uint32_t>( rva_sec );
		in_out.physical_address = scn->ptr_raw_data =     math::narrow_cast<uint32_t>( img_original_size );
		in_out.physical_size =    scn->size_raw_data =    math::narrow_cast<uint32_t>( aligned_size );
		in_out.virtual_size =     scn->virtual_size =     math::narrow_cast<uint32_t>( aligned_size );
	}

	bool pe_image::is_relocated( uint64_t rva ) const
	{
		// TODO: Handle for PE32
		//
		fassert( is_pe64() );

		// Get relocation directory.
		//
		auto dos_header = ( const dos_header_t* ) cdata();
		auto nt_header = dos_header->get_nt_headers<true>();
		const auto& reloc_dir = nt_header->optional_header.data_directories.basereloc_directory;
		if ( reloc_dir.present() )
		{
			// Get block boundaries
			const auto* block_begin = &rva_to_ptr<reloc_directory_t>( reloc_dir.rva )->first_block;
			const auto* block_end = ( const reloc_block_t* )( ( char* ) block_begin + reloc_dir.size );

			// For each block:
			for ( auto block = block_begin; block < block_end; block = block->get_next() )
			{
				// For each entry:
				for ( size_t i = 0; i < block->num_entries(); i++ )
				{
					// Push to list if basic reloc
					if ( block->entries[ i ].type == rel_based_dir64 )
					{
						uint64_t rva_reloc = uint64_t(block->base_rva) + block->entries[ i ].offset;
						if ( rva_reloc <= rva && rva < ( rva_reloc + 8 ) )
							return true;
					}
					// Throw exception if unknown relocation type
					else
					{
						fassert( block->entries[ i ].type == reloc_type_id::rel_based_absolute );
					}
				}
			}
		}
		return false;
	}
};
