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
#include <variant>
#include <string>
#include <vtil/io>
#include <vtil/utility>
#include <vtil/symex>
#include "pointer.hpp"
#include "../arch/register_desc.hpp"
#include "../routine/basic_block.hpp"

// Forward declare tracer type.
//
namespace vtil { struct tracer; };

namespace vtil::symbolic
{
	// Dummy iterator to be used when variable is not being tracked within a block.
	//
	inline const il_const_iterator free_form_iterator = [ ] ()
	{
		// Create a dummy block with a nop and reference it.
		//
		static basic_block dummy_block{ nullptr, 0 };
		return dummy_block.emplace( dummy_block.begin(), &ins::nop );
	}();

	// Structure describing how an instruction accesses a variable.
	//
	struct access_details
	{
		// Relative offset to the variable, in bits.
		//
		bitcnt_t bit_offset = 0;

		// Number of bits the instruction wrote at that offset.
		// - Note: Not necessarily all have to be overlapping with the variable.
		//
		bitcnt_t bit_count = 0;

		// Type of access.
		//
		bool read = false;
		bool write = false;
		bool unknown = false;

		// Cast to bool to check if non-null access.
		//
		explicit operator bool() const { return bit_count != 0; }

		// Check if details are unknown.
		//
		bool is_unknown() { return unknown; }
	};

	// A pseudo single-static-assignment variable describing the state of a 
	// memory location or a register at a given index into the instruction stream.
	//
	struct variable : reducable<variable>
	{
		// If register type, we just need the register descriptor.
		//
		using register_t = register_desc;

		// If memory type, we need the base register, the offset into it and
		// the size of the variable we're looking up. Since memory has to be
		// addressed in bytes, size is not in number of bits.
		//
		struct memory_t : reducable<memory_t>
		{
			// Absolute pointer as calculated.
			//
			pointer base;

			// Size of the variable in bits.
			//
			bitcnt_t bit_count;

			// Construct from base offset and size.
			//
			memory_t( pointer base = {}, bitcnt_t bit_count = 0 )
				: base( std::move( base ) ), bit_count( bit_count ) {}

			// Add a decay wrapper.
			// - Always return constant since this value should not be modified 
			//   without recomputation of the xpointers.
			//
			const expression::reference& decay() const { return base.base; }

			// Declare reduction.
			//
			REDUCE_TO( bit_count, base );
		};

		// The iterator at which this variable is read at.
		//
		il_const_iterator at = {};

		// Variant descriptor that holds either one of the variable types.
		//
		using descriptor_t = std::variant<register_t, memory_t>;
		descriptor_t descriptor;

		// Since SSA constraints are violated if the block is looping,
		// we have to add a hint to declare it branch-dependant where
		// relevant.
		//
		bool is_branch_dependant = false;

		// Default, null constructor.
		//
		variable() {}

		// Construct by iterator and the variable descriptor itself.
		//
		variable( const il_const_iterator& it, descriptor_t desc );
		variable( const il_const_iterator& it, const memory_t& desc )
			: variable( it, descriptor_t{ desc } ) {}
		variable( const il_const_iterator& it, const register_t& desc ) 
			: variable( it, descriptor_t{ desc } ) {}

		// Construct free-form with only the descriptor itself.
		//
		variable( descriptor_t desc );
		variable( const memory_t& desc ) : variable( descriptor_t{ desc } ) {}
		variable( const register_t& desc ) : variable( descriptor_t{ desc } ) {}

		// Returns whether the variable is valid or not.
		//
		bool is_valid( bool force = false ) const;

		// Swaps the current iterator.
		//
		variable& bind( il_const_iterator it ) { at = std::move( it ); return *this; }

		// Returns whether it is bound to a free-form iterator or not.
		//
		bool is_free_form() const;

		// Wrappers around std::hold_alternative for convinient type checks.
		//
		bool is_memory() const { return std::holds_alternative<memory_t>( descriptor ); }
		bool is_register() const { return std::holds_alternative<register_t>( descriptor ); }

		// Wrappers around std::get.
		//
		memory_t& mem() { return std::get<memory_t>( descriptor ); }
		const memory_t& mem() const { return std::get<memory_t>( descriptor ); }
		register_t& reg() { return std::get<register_t>( descriptor ); }
		const register_t& reg() const { return std::get<register_t>( descriptor ); }

		// Returns the size of the variable in bits.
		//
		bitcnt_t bit_count() const { return std::visit( [ ] ( auto&& desc ) { return desc.bit_count; }, descriptor ); }

		// Conversion to symbolic expression.
		//
		expression to_expression( bool unpack = true ) const;

		// Conversion to human-readable format.
		//
		std::string to_string() const;

		// Declare reduction.
		//
		REDUCE_TO( at.block, at.entry, descriptor, is_branch_dependant );

		// Packs all the variables in the expression where it'd be optimal.
		//
		static expression::reference& pack_all( expression::reference& exp );
		[[nodiscard]] static expression::reference pack_all( const expression::reference& exp );
		[[nodiscard]] static expression pack_all( const expression& exp ) { return *pack_all( make_local_reference( &exp ) ); }

		// Checks if the variable is read by / written by / accessed by the given instruction, 
		// returns nullopt it could not be known at compile-time, otherwise the
		// access details as described by access_details. Tracer is used for
		// pointer resolving, if nullptr passed will use default tracer.
		//
		access_details read_by( const il_const_iterator& it, tracer* tr = nullptr, bool xblock = false ) const;
		access_details written_by( const il_const_iterator& it, tracer* tr = nullptr, bool xblock = false ) const;
		access_details accessed_by( const il_const_iterator& it, tracer* tr = nullptr, bool xblock = false ) const;
	};

	// Implement lazy wrappers for symbolic variable creation.
	//
	namespace impl
	{
		template<typename iterator_type>
		struct bound_memory
		{
			// Self referential temporary used to implictly declare size upon operator[] invokation.
			//
			struct size_proxy
			{
				const iterator_type& it;
				bitcnt_t n;

				// operator[](P) reads the given pointer according to the predetermined size.
				//
				auto operator[]( const pointer& p ) const { return variable( it, { p, n } ).to_expression(); }
			};

			// Iterator data is read at.
			//
			iterator_type it;

			// Default sizes memory can be accessed with..
			//
			const size_proxy qword = { it, 64 };
			const size_proxy dword = { it, 32 };
			const size_proxy word =  { it, 16 };
			const size_proxy byte =  { it, 8 };

			// Iterator copying constructor.
			//
			constexpr bound_memory( iterator_type _it ) : it{ _it } {}
			
			// Operator()(P, N) is used to read arbitrary size at [P].
			//
			auto operator()( const pointer& p, bitcnt_t n ) const { return size_proxy{ it, n }[ p ]; }
		};

		// Declare global wrapper, by default binding to free form iterator.
		//
		struct memory_wrapper : bound_memory<const il_const_iterator&>
		{
			// Inherit operator() for arbitrary size read.
			//
			using bound_memory::operator();

			// Default construction. 
			//
			constexpr memory_wrapper() : bound_memory{ free_form_iterator } {}

			// operator()( T iterator ) binds the memory state to the given iterator.
			//
			template<typename T = il_const_iterator>
			auto operator()( T&& it ) const { return bound_memory<T>{ std::forward<T>( it ) }; }
		};

		template<typename iterator_type>
		struct bound_context
		{
			// Iterator context is read at.
			//
			iterator_type it;

			// Iterator copying constructor.
			//
			constexpr bound_context( iterator_type _it ) : it{ _it } {}

			// operator[](R) reads the given register at the current iterator position.
			//
			template<typename T>
			auto operator[]( T&& id ) const { return variable( it, register_cast<std::decay_t<T>>{}( std::forward<T>( id ) ) ).to_expression(); }
		};

		struct context_wrapper : bound_context<const il_const_iterator&>
		{
			// Inherit operator[] for generic read.
			//
			using bound_context::operator[];

			// Default construction. 
			//
			constexpr context_wrapper() : bound_context{ free_form_iterator } {}

			// operator()( T iterator ) binds the context state to the given iterator.
			//
			template<typename T = il_const_iterator>
			auto operator()( T&& it ) const { return bound_context<T>{ std::forward<T>( it ) }; }
		};
	};

	static constexpr impl::memory_wrapper MEMORY = {};
	static constexpr impl::context_wrapper CTX = {};
};