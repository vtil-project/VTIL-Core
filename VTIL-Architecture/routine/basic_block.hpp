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
#include <set>
#include <list>
#include <vector>
#include <algorithm>
#include <iterator>
#include <vtil/io>
#include <vtil/utility>
#include "routine.hpp"
#include "instruction.hpp"

// [Configuration]
// Determine the stack alignment for ::pop / ::push wrappers in basic_block.
//
#ifndef VTIL_ARCH_POPPUSH_ENFORCED_STACK_ALIGN
	#define VTIL_ARCH_POPPUSH_ENFORCED_STACK_ALIGN 2
#endif

namespace vtil
{
	// Type we describe basic block timestamps in.
	//
	using epoch_t = uint64_t;
	static constexpr epoch_t invalid_epoch = ~0;

	// Descriptor for any routine that is being translated.
	// - Since optimization phase will be done in a single threaded
	//   fashion, this structure contains no mutexes at all.
	//
	// - During the translation phase, only .prev links should be
	//   accessed, under the strict condition that owning routine's
	//   mutex is held by the accesser. For the sake of "basic" 
	//   expression simplification in order to resolve branch destinations
	//   or stack pointer value when required.
	//
	// - No block should under any circumstance modify any of the properties 
	//   of any other block, with the only exception being .prev.
	//
	struct basic_block
	{
	protected:
		// Let routine access internals.
		//
		friend routine;

		// This container implements a custom std::list with certain features we need:
		// - 1) Comparison with invalid iterators should not be undefined behavior.
		// - 2) Iterator type should not abstract the container pointer.
		// - 3) Iterator operator-> | operator* should return const by default, and similar
		//      to CoW pointers should make it mutable upon the invokation of operator+,
		//      this is used to keep track of any changes to the stream so analysis passes
		//      can auto-invalidate.
		// - 4) Same goes for insert, delete, emplace_.., etc.
		//
		// Linked list entry type.
		//
		struct list_entry
		{
			list_entry* prev;
			list_entry* next;
			instruction value;
		};
	public:
		// Iterator type.
		//
		template<bool is_const>
		struct base_iterator
		{
			// Generic iterator typedefs.
			//
			using iterator_category = std::bidirectional_iterator_tag;
			using value_type =        const instruction;
			using difference_type =   int64_t;
			using pointer =           value_type*;
			using reference =         value_type&;

			// References to the block and the entry.
			//
			make_const_if_t<is_const, basic_block*> block = nullptr;
			list_entry* entry = nullptr;
			const path_set* paths_allowed = nullptr;
			bool is_path_restricted = false;

			// Basic constructors.
			//
			base_iterator() {}
			base_iterator( const basic_block* block, list_entry* entry )
				: block( make_mutable( block ) ), entry( entry ) {}

			// Default copy/move.
			//
			base_iterator( base_iterator&& ) = default;
			base_iterator( const base_iterator& ) = default;
			base_iterator& operator=( base_iterator&& ) = default;
			base_iterator& operator=( const base_iterator& ) = default;

			// Position checks.
			//
			bool is_end() const   { return !block || !entry; }
			bool is_begin() const { return !block || entry == block->head; }
			bool is_valid() const { return !is_end() || !is_begin(); }

			// Decay to const iterator.
			//
			operator const base_iterator<true>&() const { return *( const base_iterator<true>* ) this; }

			// Access semantics.
			//
			reference operator*() const { return entry->value; }
			pointer operator->() const  { return &entry->value; }
			auto* operator+() const     
			{ 
				if constexpr ( is_const )
				{
					return make_const( &entry->value );
				}
				else
				{
					block->epoch++;
					return &entry->value;
				}
			}

			// Iteration semantics.
			//
			base_iterator& operator++() { entry = entry->next; return *this; }
			base_iterator& operator--() 
			{ 
				if ( !entry )
					entry = block->tail;
				else if ( !( entry = entry->prev ) )
					entry = ( list_entry* ) 1;
				return *this; 
			}
			base_iterator operator++( int ) { auto p = *this; ++( *this ); return p; }
			base_iterator operator--( int ) { auto p = *this; --( *this ); return p; }

			// Restricts the way current iterator can recurse in, making sure
			// every path leads up-to the block specified (or none).
			//
			base_iterator& restrict_path()
			{
				paths_allowed = nullptr;
				is_path_restricted = true;
				return *this;
			}
			base_iterator& restrict_path( const basic_block* dst, bool fwd )
			{
				paths_allowed = fwd
					? &block->owner->get_path( block, dst )
					: &block->owner->get_path_bwd( block, dst );
				is_path_restricted = true;
				return *this;
			}

			// Clears any path restriction.
			//
			base_iterator& clear_restrictions()
			{
				paths_allowed = nullptr;
				is_path_restricted = false;
				return *this;
			}

			// Returns the possible paths the iterator can follow if it reaches it's end.
			//
			std::vector<base_iterator> recurse( bool fwd ) const
			{
				// Generate a list of possible iterators to continue from:
				//
				std::vector<base_iterator> output;
				for ( basic_block* dst : ( fwd ? block->next : block->prev ) )
				{
					// Skip if path is restricted and this path is not allowed.
					//
					if ( is_path_restricted )
					{
						if ( !paths_allowed ) break;
						else if ( !paths_allowed->contains( dst ) ) continue;
					}

					// Otherwise create the new iterator inheriting the path 
					// restrictions of current iterator, and save it.
					//
					auto& it = output.emplace_back();
					it = fwd ? dst->begin() : dst->end();
					it.paths_allowed = paths_allowed;
					it.is_path_restricted = is_path_restricted;
				}
				return output;
			}

			// Conversion to string.
			//
			std::string to_string() const
			{
				if ( !is_valid() ) return "invalid";
				if ( is_end() )    return format::str( "end@Block %llx", block->entry_vip );
				else               return format::str( "#%d@Block %llx", std::distance( block->begin(), *this ), block->entry_vip );
			}

			// Equality checks.
			//
			template<bool C> bool operator!=( const base_iterator<C>& o ) const { return entry != o.entry || block != o.block; }
			template<bool C> bool operator==( const base_iterator<C>& o ) const { return entry == o.entry && block == o.block; }

			// Non-deterministic hasher.
			//
			hash_t hash() const { return make_hash( block, entry ); }
		};

		// Generic container typedefs.
		//
		using value_type =        instruction;
		using difference_type =   int64_t;
		using pointer =           const instruction*;
		using reference =         const instruction&;
		using iterator =          base_iterator<false>;
		using const_iterator =    base_iterator<true>;
		using allocator =         std::allocator<list_entry>;

		// Routine that this basic block belongs to.
		//
		routine* owner = nullptr;

		// Virtual instruction pointer to the first instruction this block originated 
		// from. ::front().vip will not do the job here in case of any skipped or 
		// optimized out instructions.
		//
		vip_t entry_vip = invalid_vip;

		// List of all basic blocks that may possibly jump to this basic 
		// block and basic blocks that we may possibly jump to.
		//
		std::vector<basic_block*> prev = {}, next = {};

		// The offset of current stack pointer from the last [MOV SP, <>] if applicable, 
		// or the beginning of the basic block and the index of the stack instance.
		//
		uint32_t sp_index = 0;
		int64_t sp_offset = 0;

		// Last temporary index used.
		//
		uint32_t last_temporary_index = 0;

		// Contains the stack of labels, if it contains any entries, last entry will
		// be used to replace the vip of any instruction pushed.
		//
		std::vector<vip_t> label_stack = {};

		// Multivariate runtime context.
		//
		multivariate<basic_block> context = {};

		// Epoch provided to allow external entities determine if the block is modified or not 
		// since their last read from it in an easy and fast way.
		//
		epoch_t epoch;

		// Creates a new block bound to a new routine with the given parameters.
		//
		static basic_block* begin( vip_t entry_vip, architecture_identifier arch_id = architecture_amd64 );
		
		// Creates a new block connected to this block at the given vip, if already explored returns nullptr,
		// should still be called if the caller knowns it is explored since this function creates the linkage.
		//
		basic_block* fork( vip_t entry_vip );

		// Basic constructor and destructor, should be invoked via ::fork and ::begin, reserved for internal use.
		//
		basic_block( routine* owner, vip_t entry_vip ) 
			: owner( owner ), entry_vip( entry_vip ), epoch( make_random<uint64_t>() ) {}
		basic_block( const basic_block& o )
			: owner( o.owner ), entry_vip( o.entry_vip ), next( o.next ), prev( o.prev ),
			  sp_index( o.sp_index ), sp_offset( o.sp_offset ), last_temporary_index( o.last_temporary_index ),
			  label_stack( o.label_stack ), epoch( o.epoch )
		{
			assign( o );
		}
		~basic_block() 
		{
			// Should have either no active links.
			//
			for ( auto nxt : next )
				fassert( std::find( nxt->prev.begin(), nxt->prev.end(), this ) == nxt->prev.end() );
			for ( auto nxt : prev )
				fassert( std::find( nxt->next.begin(), nxt->next.end(), this ) == nxt->next.end() );

			// Should not have an entry in explored blocks.
			//
			if ( owner )
				for ( auto& [vip, blk] : owner->explored_blocks )
					fassert( blk != this );

			// Destroy instruction list.
			//
			clear(); 
		}

		// Begins or ends a VIP label.
		//
		basic_block* label_end()              { label_stack.pop_back(); return this; }
		basic_block* label_begin( vip_t vip ) { label_stack.emplace_back( vip ); return this; }

		// Returns whether or not block is complete, a complete block is defined as
		// any basic block that ends with a branching instruction.
		//
		bool is_complete() const { return !empty() && back().base->is_branching(); }

		// Non-deterministic hashing of the block.
		//
		hash_t hash() const { return make_hash( entry_vip, epoch, this ); }

		// Helpers for the allocation of unique temporary registers.
		//
		register_desc tmp( bitcnt_t size )
		{
			return { register_local, last_temporary_index++, size };
		}
		template<typename... params>
		auto tmp( bitcnt_t size_0, params... size_n )
		{
			return std::make_tuple( tmp( size_0 ), tmp( size_n )... );
		}

		// Generate lazy wrappers for every instruction.
		//
#define WRAP_LAZY(x)													 \
		template<typename... Tx>										 \
		basic_block* x( Tx&&... operands )								 \
		{																 \
			emplace_back( &ins:: x, std::forward<Tx>( operands )... );   \
			return this;												 \
		}
		WRAP_LAZY( mov );    WRAP_LAZY( movsx );    WRAP_LAZY( str );    WRAP_LAZY( ldd );
		WRAP_LAZY( ifs );    WRAP_LAZY( neg );      WRAP_LAZY( add );    WRAP_LAZY( sub );
		WRAP_LAZY( div );    WRAP_LAZY( idiv );     WRAP_LAZY( mul );    WRAP_LAZY( imul );
		WRAP_LAZY( mulhi );  WRAP_LAZY( imulhi );   WRAP_LAZY( rem );    WRAP_LAZY( irem );
		WRAP_LAZY( popcnt ); WRAP_LAZY( bsf );      WRAP_LAZY( bsr );    WRAP_LAZY( bnot );   
		WRAP_LAZY( bshr );   WRAP_LAZY( bshl );     WRAP_LAZY( bxor );   WRAP_LAZY( bor );    
		WRAP_LAZY( band );   WRAP_LAZY( bror );     WRAP_LAZY( brol );   WRAP_LAZY( tg );     
		WRAP_LAZY( tge );    WRAP_LAZY( te );       WRAP_LAZY( tne );    WRAP_LAZY( tle );    
		WRAP_LAZY( tl );     WRAP_LAZY( tug );      WRAP_LAZY( tuge );   WRAP_LAZY( tule );   
		WRAP_LAZY( tul );    WRAP_LAZY( js );       WRAP_LAZY( jmp );    WRAP_LAZY( vexit );  
		WRAP_LAZY( vemit );  WRAP_LAZY( vxcall );   WRAP_LAZY( nop );    WRAP_LAZY( sfence );
		WRAP_LAZY( lfence ); WRAP_LAZY( vpinr );    WRAP_LAZY( vpinw );  WRAP_LAZY( vpinrm );   
		WRAP_LAZY( vpinwm );
#undef WRAP_LAZY

		// MFENCE => { LFENCE + SFENCE }.
		//
		basic_block* vmfence() { return lfence()->sfence(); } 

		// Queues a stack shift.
		//
		basic_block* shift_sp( int64_t offset, bool merge_instance = false, const const_iterator& it = {} );

		// Emits an entire instruction using series of VEMITs.
		//
		basic_block* vemits( const std::string& assembly );

		// Push / Pop implementation using ::shift_sp and LDD/STR.
		//
		basic_block* push( const operand& op );
		basic_block* pop( const operand& op );
		basic_block* pushf() { return push( REG_FLAGS ); }
		basic_block* popf()  { return pop( REG_FLAGS ); }

		// Implement the container interface.
		//
	public:
		// Instruction list accessors.
		//
		bool empty() const               { return instruction_count == 0; }
		size_t size() const              { return instruction_count; }
		const instruction& back() const  { dassert( tail ); return tail->value; }
		const instruction& front() const { dassert( head ); return head->value; }
		instruction& wback()             { dassert( tail ); epoch++; return tail->value; }
		instruction& wfront()            { dassert( head ); epoch++; return head->value; }
		iterator begin()                 { return { this, head }; }
		iterator end()                   { return { this, nullptr }; }
		const_iterator begin() const     { return { this, head }; }
		const_iterator end() const       { return { this, nullptr }; }

		// Instruction insertion.
		//
		iterator insert( const const_iterator& pos, const instruction& value )                  { return insert_final( pos, construct_instruction( value ), true ); }
		iterator push_back( instruction&& value )                                               { return emplace( end(), std::move( value ) ); }
		iterator push_back( const instruction& value )                                          { return insert( end(), value ); }
		iterator push_front( instruction&& value )                                              { return emplace( begin(), std::move( value ) ); }
		iterator push_front( const instruction& value )                                         { return insert( begin(), value ); }
		template<typename... Tx> iterator emplace( const const_iterator& pos, Tx&&... args )    { return insert_final( pos, construct_instruction( std::forward<Tx>( args )... ), true ); }
		template<typename... Tx> instruction& emplace_back( Tx&&... args )                      { return make_mutable( *emplace( end(), std::forward<Tx>( args )... ) ); }
		template<typename... Tx> instruction& emplace_front( Tx&&... args )                     { return make_mutable( *emplace( begin(), std::forward<Tx>( args )... ) ); }

		// Same as above but skips instruction processing.
		//
		iterator np_insert( const const_iterator& pos, const instruction& value )               { return insert_final( pos, construct_instruction( value ), false ); }
		iterator np_push_back( instruction&& value )                                            { return np_emplace( end(), std::move( value ) ); }
		iterator np_push_back( const instruction& value )                                       { return np_insert( end(), value ); }
		iterator np_push_front( instruction&& value )                                           { return np_emplace( begin(), std::move( value ) ); }
		iterator np_push_front( const instruction& value )                                      { return np_insert( begin(), value ); }
		template<typename... Tx> iterator np_emplace( const const_iterator& pos, Tx&&... args ) { return insert_final( pos, construct_instruction( std::forward<Tx>( args )... ), false ); }
		template<typename... Tx> instruction& np_emplace_back( Tx&&... args )                   { return make_mutable( *np_emplace( end(), std::forward<Tx>( args )... ) ); }
		template<typename... Tx> instruction& np_emplace_front( Tx&&... args )                  { return make_mutable( *np_emplace( begin(), std::forward<Tx>( args )... ) ); }

		// Assigns a new series of instructions over the current stream.
		//
		template<typename It>
		basic_block* assign( It begin, const It& end )
		{
			// Clear instruction stream and assign each entry.
			//
			clear();
			while ( begin != end )
			{
				// Allocate a new entry at the end.
				//
				list_entry* entry = construct_instruction( *begin++ );
				entry->prev = tail;
				entry->next = nullptr;
				tail = entry;

				// Set head if first entry, else fix links; increment entry count.
				//
				if ( !head ) head = entry;
				else         entry->prev->next = entry;
				instruction_count++;
			}
			return this;
		}
		template<typename T>
		basic_block* assign( const T& o ) 
		{ 
			return assign( std::begin( o ), std::end( o ) ); 
		}

		// Instruction deletion.
		//
		iterator erase( const const_iterator& pos );
		instruction pop_front();
		instruction pop_back();
		basic_block* clear();

		// Helper used to drop const-qualifiers of an iterator when we have a mutable 
		// reference to the block itself.
		//
		iterator acquire( const_iterator&& it )             { dassert( !it.block || it.block == this ); return ( iterator&& ) it; }
		iterator& acquire( const_iterator& it )             { dassert( !it.block || it.block == this ); return ( iterator& ) it; }
		const iterator& acquire( const const_iterator& it ) { dassert( !it.block || it.block == this ); return ( const iterator& ) it; }
	
	protected:
		// Wrappers for instruction construction and deconstruction.
		//
		template<typename... Tx>
		static list_entry* construct_instruction( Tx&&... args )
		{
			list_entry* entry = allocator{}.allocate( 1 );
			new ( &entry->value ) value_type( std::forward<Tx>( args )... );
			return entry;
		}
		static void destruct_instruction( list_entry* entry )
		{
			std::destroy_at( &entry->value );
			allocator{}.deallocate( entry, 1 );
		}

		// Head and tail of the instruction list along with the size of it.
		//
		list_entry* head = nullptr;
		list_entry* tail = nullptr;
		size_t instruction_count = 0;

		// Internally invoked by emplace to insert a new linked list entry to the instruction stream.
		//
		iterator insert_final( const const_iterator& pos, list_entry* new_entry, bool process );
	};

	// Escape basic block namespace for the iterator type 
	// for the sake of convinience.
	//
	using il_iterator =       basic_block::iterator;
	using il_const_iterator = basic_block::const_iterator;
};	