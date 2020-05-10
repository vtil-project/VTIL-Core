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
#include <set>
#include <list>
#include <vector>
#include <algorithm>
#include <iterator>
#include <vtil/utility>
#include "routine.hpp"
#include "instruction.hpp"

namespace vtil
{
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
		// Define a range iterator so queries can be used on this structure.
		//
		template<typename _container_type, typename _iterator_type>
		struct riterator_base : _iterator_type
		{
			using container_type = _container_type;
			using iterator_type = _iterator_type;

			// Reference to the block.
			//
			container_type* container = nullptr;

			// Path restriction state.
			//
			bool is_path_restricted = false;
			std::set<container_type*> paths_allowed;

			// Default constructor and the block-bound constructor.
			//
			riterator_base() {}
			riterator_base( container_type* ref, const iterator_type& i ): container( ref ), iterator_type( i ) {}
			template<typename X, typename Y> riterator_base( const riterator_base<X, Y>& o ) : container( o.container ), iterator_type( Y( o ) ) {}

			// Override equality operators to check container first.
			//
			bool operator!=( const riterator_base& o ) const { return container != o.container || ((const iterator_type&)*this) != o; }
			bool operator==( const riterator_base& o ) const { return container == o.container && ((const iterator_type&)*this) == o; }

			// Simple position/validity checks.
			//
			bool is_end() const { return !container || operator==( { container, container->stream.end() } ); }
			bool is_begin() const { return !container || operator==( { container, container->stream.begin() } ); }
			bool is_valid() const { return !is_begin() || !is_end(); }

			// Simple helper used to trace paths towards a container.
			//
			static std::set<container_type*> path_to( container_type* src, container_type* dst,
													  bool forward, std::set<container_type*> path = {} )
			{
				// If we've already tried this path, fail.
				//
				if ( path.find( src ) != path.end() )
					return {};

				// Insert <src> into path.
				//
				path.insert( src );

				// If we reached our destination, report success.
				//
				if ( src == dst )
					return path;

				// Otherwise, recurse.
				//
				std::set<container_type*> paths_allowed;
				for ( container_type* blk : ( forward ? src->next : src->prev ) )
				{
					// If path ended up at destination, mark all paths "allowed".
					//
					std::set<container_type*> path_taken = path_to( blk, dst, forward, path );
					if ( !path_taken.empty() )
						paths_allowed.insert( path_taken.begin(), path_taken.end() );
				}
				return paths_allowed;
			}

			// Restricts the way current iterator can recurse in, making sure
			// every path leads up-to the container specified.
			//
			void restrict_path( container_type* dst, bool forward )
			{
				// Trace the path.
				//
				std::set<container_type*> trace = path_to( container, dst, forward );
				
				// If path is already restricted:
				//
				if ( is_path_restricted )
				{
					// Any allowed path should be allowed in both now. 
					//
					std::set<container_type*> path_intersection;
					std::set_intersection( trace.begin(), trace.end(), 
										   paths_allowed.begin(), paths_allowed.end(), 
										   std::inserter( path_intersection, path_intersection.begin() ) );
					paths_allowed = path_intersection;
				}
				else
				{
					// Set as the current allowed paths list.
					//
					paths_allowed = trace;
				}

				// Declare the current iterator path restricted.
				//
				is_path_restricted = true;
			}

			// Returns the possible paths the iterator can follow if it reaches it's end.
			//
			std::vector<riterator_base> recurse( bool forward ) const
			{
				// Generate a list of possible iterators to continue from:
				//
				std::vector<riterator_base> output;
				for ( container_type* dst : ( forward ? container->next : container->prev ) )
				{
					// Skip if path is restricted and this path is not allowed.
					//
					if ( is_path_restricted && paths_allowed.find( dst ) == paths_allowed.end() )
						continue;

					// Otherwise create the new iterator, inheriting the path restrictions 
					// of current iterator, and save it.
					// 
					riterator_base new_it = { dst,  forward ? dst->begin() : dst->end() };
					new_it.paths_allowed = paths_allowed;
					new_it.is_path_restricted = is_path_restricted;
					output.push_back( new_it );
				}
				return output;
			}
		};
		using iterator =       riterator_base<basic_block, std::list<instruction>::iterator>;
		using const_iterator = riterator_base<const basic_block, std::list<instruction>::const_iterator>;

		// Routine that this basic block belongs to.
		//
		routine* owner = nullptr;
		
		// Virtual instruction pointer to the first instruction this 
		// block originated from. Looking up the instruction stream 
		// will not do the job here in-case of any skipped or 
		// optimized out instructions.
		//
		vip_t entry_vip = invalid_vip;

		// List of all basic blocks that may possibly 
		// jump to this basic block.
		//
		std::vector<basic_block*> prev = {};

		// The offset of current stack pointer from the last 
		// [MOV SP, <>] if applicable, or the beginning of 
		// the basic block and the index of the stack instance.
		//
		int64_t sp_offset = 0;
		uint32_t sp_index = 0;

		// List of all basic blocks that this basic
		// block may possibly jump to.
		//
		std::vector<basic_block*> next = {};

		// List of all instructions in the stream. This structure
		// is represented as a list instead to make all references
		// to it valid even if an element is appended/removed.
		//
		std::list<instruction> stream = {};

		// Last temporary index used.
		//
		uint32_t last_temporary_index = 0;

		// Wrap the std::list fundamentals.
		//
		auto size() const { return stream.size(); }
		iterator end() { return { this, stream.end() }; }
		iterator begin() { return { this, stream.begin() }; }
		const_iterator end() const { return { this, stream.end() }; }
		const_iterator begin() const { return { this, stream.begin() }; }

		// Returns whether or not block is complete, a complete
		// block ends with a branching instruction.
		//
		bool is_complete() const { return !stream.empty() && stream.back().base->is_branching(); }
		
		// Constructor does not exist. Should be created either using
		// ::begin(...) or ->fork(...).
		//
		static basic_block* begin( vip_t entry_vip );
		basic_block* fork( vip_t entry_vip );

		// Helpers for the allocation of unique temporary registers
		//
		register_desc tmp( uint8_t size );
		template<typename... params>
		auto tmp( uint8_t size_0, params... size_n )
		{
			return std::make_tuple( tmp( size_0 ), tmp( size_n )... );
		}

		// Instruction pre-processor
		//
		void append_instruction( instruction&& ins );
		void append_instruction( const instruction& ins ) { append_instruction( instruction{ ins } ); }

		// Lazy wrappers for every instruction
		//
		template<typename _T>
		auto prepare_operand( _T&& value )
		{
			using T = std::remove_cvref_t<_T>;

			// If integer, describe as one.
			//
			if constexpr ( std::is_integral_v<T> )
				return operand( value, sizeof( T ) * 8 );
			// Otherwise try explicitly casting.
			//
			else
				return operand( value );
		}

#define WRAP_LAZY(x)																											                \
		template<typename... Ts>																								                \
		basic_block* x ( Ts&&... operands )																						                \
		{																														                \
			append_instruction( instruction{ &ins:: x, std::vector<operand>( { prepare_operand(std::forward<Ts>(operands))... } ) } );			\
			return this;																										                \
		}
		WRAP_LAZY( mov );
		WRAP_LAZY( str );
		WRAP_LAZY( ldd );
		WRAP_LAZY( neg );
		WRAP_LAZY( add );
		WRAP_LAZY( sub );
		WRAP_LAZY( div );
		WRAP_LAZY( idiv );
		WRAP_LAZY( mul );
		WRAP_LAZY( imul );
		WRAP_LAZY( mulhi );
		WRAP_LAZY( imulhi );
		WRAP_LAZY( rem );
		WRAP_LAZY( irem );
		WRAP_LAZY( bnot );
		WRAP_LAZY( bshr );
		WRAP_LAZY( bshl );
		WRAP_LAZY( bxor );
		WRAP_LAZY( bor );
		WRAP_LAZY( band );
		WRAP_LAZY( bror );
		WRAP_LAZY( brol );
		WRAP_LAZY( upflg );
		WRAP_LAZY( js );
		WRAP_LAZY( jmp );
		WRAP_LAZY( vexit );
		WRAP_LAZY( vemit );
		WRAP_LAZY( vxcall );
		WRAP_LAZY( nop );
		WRAP_LAZY( vpinr );
		WRAP_LAZY( vpinw );
		WRAP_LAZY( vpinrm );
		WRAP_LAZY( vpinwm );
#undef WRAP_LAZY

		// Queues a stack shift.
		//
		basic_block* shift_sp( int64_t offset, bool merge_instance = false, iterator it = {} );

		// Pushes current flags value up the stack queueing the
		// shift in stack pointer.
		//
		basic_block* pushf();

		// Emits an entire instruction using series of VEMITs.
		//
		basic_block* vemits( const std::string& assembly );

		// Pushes an operand up the stack queueing the
		// shift in stack pointer.
		//
		template<typename T, uint8_t stack_alignment = 2>
		basic_block* push( const T& _op )
		{
			operand op = prepare_operand( _op );

			// Handle SP specially since we change the stack pointer
			// before the instruction begins.
			//
			if ( op.is_register() && op.reg().is_stack_pointer() )
			{
				auto t0 = tmp( 64 );
				return mov( t0, op )->push( t0 );
			}

			shift_sp( op.size() < stack_alignment ? -stack_alignment : -int64_t( op.size() ) );
			str( REG_SP, sp_offset, op );
			return this;
		}

		// Pops an operand from the stack queueing the
		// shift in stack pointer.
		//
		template<typename T, uint8_t stack_alignment = 2>
		basic_block* pop( const T& _op )
		{
			operand op = prepare_operand( _op );
			int64_t offset = sp_offset;
			shift_sp( op.size() < stack_alignment ? stack_alignment : op.size() );
			ldd( op, REG_SP, offset );
			return this;
		}

		// Generates a hash for the block.
		//
		hash_t hash() const;
	};

	// Escape basic block namespace for the iterator type 
	// for the sake of convinience.
	//
	using il_iterator =       basic_block::iterator;
	using il_const_iterator = basic_block::const_iterator;
};