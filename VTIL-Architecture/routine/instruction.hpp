#pragma once
#include <vector>
#include <string>
#include "..\arch\instruction_set.hpp"
#include "..\misc\format.hpp"

namespace vtil
{
	// Remove the arch:: prefix from register view, operand and instructions as it 
	// gets very redundant since it's commonly used in instruction creation.
	//
	using register_view = arch::register_view;
	using operand = arch::operand;
	namespace ins = arch::ins;

	// Simple helper to create an immediate operand since vtil::operand( v, size ) gets redundant.
	//
	template<typename T> static operand make_imm( T value ) { return operand( value, sizeof( T ) ); }

	// Type we use to describe virtual instruction pointer in.
	//
	using vip_t = uint64_t;
	static constexpr vip_t invalid_vip = -1;

	// This structure is used to describe instances of VTIL instructions in
	// the instruction stream.
	//
	struct instruction
	{
		// Base instruction type.
		//
		const arch::instruction_desc* base;

		// List of operands.
		//
		std::vector<operand> operands;

		// Virtual instruction pointer that this instruction
		// originally was generated based on.
		//
		vip_t vip = invalid_vip;

		// Whether the instruction was explicitly declared volatile.
		//
		bool explicit_volatile = false;

		// Basic constructor, non-default constructor asserts the constructed
		// instruction is valid according to the instruction descriptor.
		//
		instruction() {}
		instruction( const arch::instruction_desc* base,
					 const std::vector<operand>& operands = {},
					 vip_t vip = invalid_vip,
					 bool explicit_volatile = false ) :
			base( base ), operands( operands ),
			vip( vip ), explicit_volatile( explicit_volatile )
		{
			fassert( is_valid() );
		}

		// Returns whether the instruction is valid or not.
		//
		bool is_valid() const
		{
			// Instruction must have a base descriptor assigned.
			//
			if ( !base )
				return false;

			// Validate operand count.
			//
			if ( operands.size() != base->operand_count() )
				return false;

			// Validate operand types against the base access type.
			//
			for ( int i = 0; i < base->access_types.size(); i++ )
			{
				if ( !operands[ i ].is_valid() )
					return false;
				if ( base->access_types[ i ] == arch::read_imm && !operands[ i ].is_immediate() )
					return false;
				if ( base->access_types[ i ] == arch::read_reg && !operands[ i ].is_register() )
					return false;
			}

			// Validate memory operands.
			//
			if ( base->accesses_memory() )
			{
				const operand& mem_base = operands[ base->access_size_index ];
				const operand& mem_offset = operands[ base->access_size_index + 1 ];
				if ( !mem_base.is_register() || mem_base.size() != 8 )
					return false;
				if ( !mem_offset.is_immediate() )
					return false;
			}

			// Validate branching operands.
			//
			for ( auto& list : { base->branch_operands_rip, base->branch_operands_vip } )
			{
				for ( int idx : list )
				{
					if ( operands[ idx ].size() != 8 )
						return false;
				}
			}
			return true;
		}


		// Makes the instruction explicitly volatile.
		//
		auto& make_volatile() { explicit_volatile = true; return *this; }

		// Returns whether this instruction was directly translated
		// from a virtual machine instruction or not
		//
		bool is_pseudo() const { return vip == invalid_vip; }

		// Returns whether the instruction is volatile or not.
		//
		bool is_volatile() const { return explicit_volatile || base->is_volatile; }

		// Returns the access size of the instruction.
		//
		size_t access_size() const { return operands.empty() ? 0 : operands[ base->access_size_index ].size(); }

		// Returns all memory accesses matching the criteria.
		//
		std::pair<arch::register_view, int64_t> get_mem_loc( arch::operand_access access = arch::invalid ) const
		{
			// Validate arguments.
			//
			fassert( access == arch::invalid || access == arch::read || access == arch::write );

			// If instruction does access memory:
			//
			if ( base->accesses_memory() )
			{
				// Fetch and validate memory operands pair.
				//
				const register_view& mem_base = operands[ base->access_size_index ].reg;
				const operand& mem_offset = operands[ base->access_size_index + 1 ];

				if ( !base->memory_write && ( access == arch::read || access == arch::invalid ) )
					return { mem_base, mem_offset.i64 };
				else if ( base->memory_write && ( access == arch::write || access == arch::invalid ) )
					return { mem_base, mem_offset.i64 };
			}
			return {};
		}

		// Checks whether the instruction reads from the given register or not.
		//
		bool reads_from( const register_view& rw ) const
		{
			for ( int i = 0; i < base->access_types.size(); i++ )
				if ( base->access_types[ i ] != arch::write && operands[ i ].reg.overlaps( rw ) )
					return true;
			return false;
		}

		// Checks whether the instruction writes to the given register or not.
		//
		bool writes_to( const register_view& rw ) const
		{
			for ( int i = 0; i < base->access_types.size(); i++ )
				if ( base->access_types[ i ] >= arch::write && operands[ i ].reg.overlaps( rw ) )
					return true;
			return false;
		}

		// Checks whether the instruction overwrites the given register or not.
		//
		bool overwrites( const register_view& rw ) const
		{
			for ( int i = 0; i < base->access_types.size(); i++ )
				if ( base->access_types[ i ] == arch::write && operands[ i ].reg.overlaps( rw ) )
					return true;
			return false;
		}

		// Basic comparison operators.
		//
		bool operator==( const instruction& o ) const { return base == o.base && operands == o.operands; }
		bool operator!=( const instruction& o ) const { return !operator==( o ); }
		bool operator<( const instruction& o ) const { return vip < o.vip; }

		// Conversion to human-readable format.
		//
		std::string to_string() const
		{
			std::vector<std::string> operand_str;
			for ( auto& op : operands )
				operand_str.push_back( op.to_string() );
			fassert( operand_str.size() <= arch::max_operand_count &&
					 arch::max_operand_count == 4 );
			operand_str.resize( arch::max_operand_count );

			return format::str
			(
				FMT_INS,
				base->to_string( access_size() ),
				operand_str[ 0 ],
				operand_str[ 1 ],
				operand_str[ 2 ],
				operand_str[ 3 ]
			);
		}
	};
};
