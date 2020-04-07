#pragma once
#include <set>
#include <list>
#include <vector>
#include <algorithm>
#include <iterator>
#include <keystone.hpp>
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
	// - No block should under any 
	//   circumstance modify any of the properties of any other block, 
	//   with the only exception being .prev.
	//
	struct basic_block
	{
		// Define a range iterator so queries can be used on this structure.
		//
		template<typename container_type, typename iterator_type>
		struct riterator_base : iterator_type
		{
			using container_type = container_type;
			using iterator_type = iterator_type;

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
			bool operator!=( const riterator_base& o ) const { return container != o.container || iterator_type::operator!=( o ); }
			bool operator==( const riterator_base& o ) const { return container == o.container && iterator_type::operator==( o ); }

			// Simple position/validity checks.
			//
			bool is_end() const { return !container || iterator_type::operator==( ( iterator_type ) container->stream.end() ); }
			bool is_begin() const { return !container || iterator_type::operator==( ( iterator_type ) container->stream.begin() ); }
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
		using iterator = riterator_base<basic_block, std::list<instruction>::iterator>;
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
		// [MOV RSP, <>] if applicable, or the beginning of 
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

		// Wrap the std::list fundamentals.
		//
		auto size() const { return stream.size(); }
		iterator end() { return { this, stream.end() }; }
		iterator begin() { return { this, stream.begin() }; }
		const_iterator end() const { return { this, stream.end() }; }
		const_iterator begin() const { return { this, stream.begin() }; }

		// Returns whether or not stream is complete.
		//
		bool is_complete() const
		{
			// Instructions cannot be appended after a branching instruction was hit.
			//
			return !stream.empty() && stream.back().base->is_branching();
		}
		
		// Constructor does not exist. Should be created either using
		// ::begin(...) or ->fork(...).
		//
		static basic_block* begin( vip_t entry_vip )
		{
			// Caller must provide a valid virtual instruction pointer.
			//
			fassert( entry_vip != invalid_vip );

			// Create the basic block with depth = 0, identifier = "0"
			//
			basic_block* blk = new basic_block;
			blk->entry_vip = entry_vip;

			// Create the routine and assign this block as the entry-point
			//
			blk->owner = new routine;
			blk->owner->entry_point = blk;
			blk->owner->explored_blocks[ entry_vip ] = blk;

			// Return the block
			//
			return blk;
		}
		basic_block* fork( vip_t entry_vip )
		{

			// Block cannot be forked before a branching instruction is hit.
			//
			fassert( is_complete() );

			// Caller must provide a valid virtual instruction pointer.
			//
			fassert( entry_vip != invalid_vip );

			// Check if the routine has already explored this block.
			//
			std::lock_guard g( owner->mutex );
			basic_block* result = nullptr;
			basic_block*& entry = owner->explored_blocks[ entry_vip ];
			if ( !entry )
			{
				// If it did not, create a block and assign it.
				//
				result = new basic_block;
				result->owner = owner;
				result->entry_vip = entry_vip;
				result->sp_offset = 0;
				entry = result;
			}

			// Fix the links and quit the scope holding the lock.
			//
			next.push_back( entry );
			entry->prev.push_back( this );
			return result;
		}

		// Helpers for the allocation of unique temporary registers
		//
		auto tmp( uint8_t size )
		{
			return arch::register_view
			{
				"t" + std::to_string( ++owner->temporary_index_counter ),
				0,
				size
			};
		}
		template<typename... params>
		auto tmp( uint8_t size_0, params... size_n )
		{
			return std::make_tuple( tmp( size_0 ), tmp( size_n )... );
		}

		// Instruction pre-processor
		//
		void append_instruction( instruction ins )
		{
			// Instructions cannot be appended after a branching instruction was hit.
			//
			fassert( !is_complete() );

			// Write the stack pointer details.
			//
			ins.sp_offset = sp_offset;
			ins.sp_index = sp_index;

			// If instruction writes to RSP, reset the queued stack pointer.
			//
			if ( ins.writes_to( X86_REG_RSP ) )
			{
				sp_offset = 0;
				sp_index++;
				ins.sp_reset = true;
			}

			// Append the instruction to the stream.
			//
			stream.push_back( ins );
		}

		// Lazy wrappers for every instruction
		//
		template<typename T>
		operand prepare_operand( const T& value )
		{
			// If register_view or operand, return as is.
			//
			if constexpr ( std::is_same_v<T, register_view> ||
						   std::is_same_v<T, operand> )
				return operand( value );
			// If x86_reg, map to register_view
			//
			else if constexpr ( std::is_same_v<T, x86_reg> )
			{
				auto [offset, size] = arch::get_register_mapping( value );
				return operand( register_view( value, offset, size ) );
			}
			// If std::string/register_desc, cast to register_view
			//
			else if constexpr ( std::is_same_v<T, std::string> ||
								std::is_same_v<T, arch::register_desc> )
				return operand( register_view( value ) );
			// Else, treat as immediate
			//
			else if constexpr ( std::is_integral_v<T> )
				return operand( value, sizeof( T ) );
			
			// Failed to parse operand of lazy call.
			//
			unreachable();
			return {};
		}

#define WRAP_LAZY(x)																											\
		template<typename ...Ts>																								\
		basic_block* x ( Ts... operands )																								\
		{																														\
			append_instruction( instruction{ &ins:: x, std::vector<operand>( { prepare_operand(operands)... } ) } );			\
			return this;																										\
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
		WRAP_LAZY( js );
		WRAP_LAZY( jmp );
		WRAP_LAZY( vexit );
		WRAP_LAZY( vemit );
		WRAP_LAZY( vxcall );
		WRAP_LAZY( nop );
		WRAP_LAZY( vcmp0 );
		WRAP_LAZY( vpinr );
		WRAP_LAZY( vpinw );
		WRAP_LAZY( vpinrm );
		WRAP_LAZY( vpinwm );
#undef WRAP_LAZY

		// Queues a stack shift.
		//
		basic_block* shift_sp( int64_t offset, bool merge_instance = false, iterator it = {} )
		{
			// If requested, shift the stack index first.
			//
			if ( merge_instance )
			{
				// Assert instruction at iterator indeed resets stack pointer.
				//
				fassert( !it.is_end() && it->sp_reset );
				
				// Decrement stack index for each instruction afterwards.
				//
				for ( auto i = std::next( it ); !i.is_end(); i++ )
					i->sp_index--;
				sp_index--;
				
				// Remove the reset flag and merge the offsets.
				//
				it->sp_reset = false;
				offset += it->sp_offset;
				it->sp_offset = 0;
			}

			// If an iterator is provided, shift the stack pointer
			// for every instruction that precedes it as well.
			//
			std::optional<uint32_t> sp_index_prev;
			while ( !it.is_end() )
			{
				// Shift the stack offset accordingly.
				//
				it->sp_offset += offset;

				// If instruction reads from RSP:
				//
				if ( it->reads_from( X86_REG_RSP ) )
				{
					// If LDR|STR with memory operand RSP:
					//
					if ( it->base->accesses_memory() && it->operands[ it->base->memory_operand_index ].reg == X86_REG_RSP )
					{
						// Assert the offset operand is an immediate and 
						// shift the offset as well.
						//
						fassert( it->operands[ it->base->memory_operand_index + 1 ].is_immediate() );
						it->operands[ it->base->memory_operand_index + 1 ].i64 += offset;
					}
				}

				// If stack changed changed, return, else forward the iterator.
				//
				if ( sp_index_prev.value_or( it->sp_index ) != it->sp_index )
					return this;
				sp_index_prev = it->sp_index;
				++it;
			}

			// Shift the stack pointer and continue as usual
			// without emitting any sub or add instructions.
			// Queued stack pointer changes will be processed
			// in bulk at the end of the routine.
			//
			sp_offset += offset;
			return this;
		}

		// Pushes an operand up the stack queueing the
		// shift in stack pointer.
		//
		template<typename T, uint8_t stack_alignment = 2>
		basic_block* push( const T& _op )
		{
			operand op = prepare_operand( _op );

			// Handle RSP specially since we change the stack pointer
			// before the instruction begins.
			//
			if ( op.is_register() && op.reg.base == X86_REG_RSP )
			{
				auto t0 = tmp( 8 );
				return mov( t0, op )->push( t0 );
			}
			
			shift_sp( op.size() < stack_alignment ? -stack_alignment : -op.size() );
			str( X86_REG_RSP, sp_offset, op );
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
			ldd( op, X86_REG_RSP, offset );
			return this;
		}

		// Pushes current flags value up the stack queueing the
		// shift in stack pointer.
		//
		basic_block* pushf()
		{
			return push( X86_REG_EFLAGS );
		}

		// Emits an entire instruction using series of VEMITs.
		//
		basic_block* vemits( const std::string& assembly )
		{
			auto res = assemble( assembly );
			fassert( !res.empty() );
			for ( uint8_t byte : res )
				vemit( byte );
			return this;
		}
	};

	// Export iterator type for the sake of convinience.
	// - It's called stream here because these iterators 
	//   are recursive range iterators.
	//
	using ilstream_iterator = basic_block::iterator;
	using ilstream_const_iterator = basic_block::const_iterator;
};