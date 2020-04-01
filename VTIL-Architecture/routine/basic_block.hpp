#pragma once
#define STRICT_STACK_TRACKING 0

#include <vector>
#include <list>
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
		template<typename _container_type, typename _iterator_type>
		struct riterator_base : _iterator_type
		{
			using container_type = _container_type;
			using iterator_type = _iterator_type;

			// Reference to the block.
			//
			container_type* container = nullptr;

			// Default constructor and the block-bound constructor.
			//
			riterator_base() {}
			riterator_base( container_type* ref, const iterator_type& i ): container( ref ), iterator_type( i ) {}
			template<typename X, typename Y> riterator_base( const riterator_base<X, Y>& o ) : container( o.container ), iterator_type( o ) {}

			// Simple position/validity checks.
			//
			bool is_end() const { return !container || _iterator_type::operator==( ( _iterator_type ) container->stream.end() ); }
			bool is_begin() const { return !container || _iterator_type::operator==( ( _iterator_type ) container->stream.begin() ); }
			bool is_valid() const { return !is_begin() || !is_end(); }

			// Returns the possible paths the iterator can follow if it reaches it's end.
			//
			std::vector<riterator_base> recurse( bool forward ) const
			{
				std::vector<riterator_base> output;
				if ( forward )
					for ( container_type* next : container->next )
						output.push_back( { next, next->begin() } );
				else
					for ( container_type* prev : container->prev )
						output.push_back( { prev, prev->end() } );
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

		// The offset of current stack pointer from the
		// last [MOV RSP, <>] if applicable, or the entry point.
		//
		int64_t stack_offset = 0;
		int64_t stack_offset_hinted = 0;

		// Types of variables inherited from the previous block.
		//
		bool inherits_stack = false;
		bool inherits_registers = false;

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
			blk->inherits_stack = false;
			blk->inherits_registers = false;

			// Create the routine and assign this block as the entry-point
			//
			blk->owner = new routine;
			blk->owner->entry_point = blk;
			blk->owner->explored_blocks[ entry_vip ] = blk;

			// Return the block
			//
			return blk;
		}
		basic_block* fork( vip_t entry_vip,
						   bool inherits_stack,
						   bool inherits_registers )
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
				result->inherits_stack = inherits_stack;
				result->inherits_registers = inherits_registers;
				result->stack_offset = stack_offset - stack_offset_hinted;
				result->stack_offset_hinted = 0;

				// Assign the new block as the cached entry.
				//
				entry = result;
			}
			else
			{
				// If it did, assert generic properties do not change.
				//
#if STRICT_STACK_TRACKING
				fassert( ( entry->stack_offset - entry->stack_offset_hinted ) ==
						 ( stack_offset - stack_offset_hinted ) );
#endif
				fassert( entry->inherits_stack == inherits_stack );
				fassert( entry->inherits_registers == inherits_registers );
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
			// Use ::set_sp(...) or ::shift_sp_queued(...) instead when writing into RSP
			//
			fassert( !ins.writes_to( X86_REG_RSP ) );

			// Use ::read_sp(...) instead when reading from RSP
			//
			fassert( ins.base == &arch::ins::str ||
					 ins.base == &arch::ins::ldd ||
					 !ins.reads_from( X86_REG_RSP ) );

			// Basic validation of operands.
			//
			fassert( ins.operands.size() == ins.base->operand_count() );
			for ( int i = 0; i < ins.base->access_types.size(); i++ )
			{
				if ( ins.base->access_types[ i ] == arch::read_imm )
					fassert( ins.operands[ i ].is_immediate() );
				else if ( ins.base->access_types[ i ] != arch::read_any )
					fassert( ins.operands[ i ].is_register() );
				else
					fassert( ins.operands[ i ].is_valid() );
			}

			// Branching operands must always be 64-bits.
			//
			for ( int idx : ins.base->branch_operands )
				fassert( ins.operands[ abs( idx ) - 1 ].size() == 8 );

			// Instructions cannot be appended after a branching instruction was hit.
			//
			fassert( !is_complete() );

			// If instruction is str and we're reading from either non-stack
			// memory or an external memory, mark volatile.
			//
			if ( ins.base == &ins::str )
			{
				if ( ins.operands[ 0 ].reg != X86_REG_RSP ||
					 ins.operands[ 1 ].i64 > stack_offset )
				{
					ins.make_volatile();
				}
			}

			// Append the instruction to the stream.
			//
			stream.push_back( ins );

			// If instruction is writing to an unknown pointer all memory and symbolic 
			// stack values will be volatile afterwards. Ideally the instruction stream 
			// translator should generate an expression for this operand and try to rewrite 
			// it in the form of [RSP + C] where possible.
			//
			if ( ins.base == &ins::str && 
				 ins.operands[ 0 ].reg != X86_REG_RSP )
			{
				// Hint that all memory is volatile afterwards.
				//
				vhmemv();
			}
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
		auto* x ( Ts... operands )																								\
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
		WRAP_LAZY( bnot );
		WRAP_LAZY( bshr );
		WRAP_LAZY( bshl );
		WRAP_LAZY( bxor );
		WRAP_LAZY( bor );
		WRAP_LAZY( band );
		WRAP_LAZY( bnor );
		WRAP_LAZY( bnand );
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
		WRAP_LAZY( vhmemv );
		WRAP_LAZY( vhspsh );
#undef WRAP_LAZY

		// Queues a stack shift.
		//
		auto* shift_sp_queued( int64_t offset )
		{
			// Shift the stack pointer and continue as usual
			// without emitting any sub or add instructions.
			// Queued stack pointer changes will be processed
			// in bulk at the end of the routine.
			//
			stack_offset += offset;
			return this;
		}

		// Shifts the stack pointer immediately.
		//
		auto* shift_sp( int64_t offset )
		{
			// Skip if no-op.
			//
			if ( !offset ) 
				return this;

			// Append a VHINTSPSH Imm64.
			//
			vhspsh( offset );

			// Queue stack shift.
			//
			shift_sp_queued( offset );

			// Let the stream know that we added a hint for this
			// shift already.
			//
			stack_offset_hinted += offset;
			return this;
		}

		// Changes the stack pointer. Ideally the instruction stream 
		// translator should generate an expression for this operand and try to rewrite 
		// it in the form of [RSP + C] where possible, and call ::shift_sp(...) instead.
		//
		template<typename T>
		auto* set_sp( const T& _op )
		{
			operand op = prepare_operand( _op );

			// Skip if no-op.
			//
			if ( op.reg == X86_REG_RSP )
				return this;

			// Append a explicitly volatile [MOV RSP, Reg/Imm64]
			//
			stream.push_back( instruction{ &ins::mov, { register_view{ X86_REG_RSP }, op } }.make_volatile() );

			// Append a VHMEMV
			//
			vhmemv();

#if STRICT_STACK_TRACKING
			// Assert that stack was balanced prior to the execution
			// of this instruction.
			//
			fassert( stack_offset == stack_offset_hinted );
			stack_offset = 0;
			stack_offset_hinted = 0;
#else
			// Reset stack offset whilist keeping the alignment property
			// intact. If stack pointer was not aligned, we'll set
			// +8 as the new stack pointer and hint the actual value 
			// to the compiler instead.
			//
			stack_offset = stack_offset & 8;
			stack_offset_hinted = 0;
			if ( stack_offset )
				vhspsh( -stack_offset );
#endif

			return this;
		}

		// Pushes an operand up the stack queueing the
		// shift in stack pointer.
		//
		template<typename T, uint8_t stack_alignment = 2>
		auto* push( const T& _op )
		{
			operand op = prepare_operand( _op );
			shift_sp_queued( op.size() < stack_alignment ? -stack_alignment : -op.size() );
			str( X86_REG_RSP, stack_offset, op );
			return this;
		}

		// Pops an operand from the stack queueing the
		// shift in stack pointer.
		//
		template<typename T, uint8_t stack_alignment = 2>
		auto* pop( const T& _op )
		{
			operand op = prepare_operand( _op );
			ldd( op, X86_REG_RSP, stack_offset );
			shift_sp_queued( op.size() < stack_alignment ? stack_alignment : op.size() );
			return this;
		}

		// Reads the stack pointer into the operand
		// specified.
		//
		template<typename T>
		auto* read_sp( const T& _op )
		{
			operand op = prepare_operand( _op );
			fassert( op.size() == 8 );
			stream.push_back( { &ins::mov, { op, register_view{ X86_REG_RSP } } } );
			stream.push_back( { &ins::add, { op, make_imm( stack_offset )} } );
			return this;
		}

		// Pushes current flags value up the stack queueing the
		// shift in stack pointer.
		//
		auto* pushf()
		{
			return push( X86_REG_EFLAGS );
		}

		// Emits an entire instruction using series of VEMITs.
		//
		auto* vemits( const std::string& assembly )
		{
			auto res = assemble( assembly );
			fassert( !res.empty() );
			for ( uint8_t byte : res )
				vemit( byte );
			return this;
		}
	};
};