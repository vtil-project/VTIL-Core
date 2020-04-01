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

		// Whether the instruction was explicitly declared volatile
		//
		bool explicit_volatile = false;

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

		// Lists all register operands matching the criteria
		//
		template<typename C, arch::operand_access V, typename T = operand>
		std::vector<T*> enum_reg() const
		{
			std::vector<T*> res;
			for ( int i = 0; i < base->access_types.size(); i++ )
				if ( C{}( base->access_types[ i ], V ) && operands[ i ].is_register() )
					res.push_back( &operands[ i ] );
			return res;
		}

		// Checks whether the instruction reads from the given register or not.
		//
		const operand* reads_from( const register_view& rw ) const
		{
			auto reads = enum_reg<std::not_equal_to<>, arch::write, const operand>();
			for ( auto rd : reads )
				if ( rd->reg.overlaps( rw ) )
					return rd;
			return false;
		}

		// Checks whether the instruction writes to the given register or not.
		//
		const operand* writes_to( const register_view& rw ) const
		{
			auto writes = enum_reg<std::greater_equal<>, arch::write, const operand>();
			for ( auto wr : writes )
				if ( wr->reg.overlaps( rw ) )
					return wr;
			return false;
		}

		// Checks whether the instruction writes to the given register or not.
		//
		const operand* overwrites( const register_view& rw ) const
		{
			auto writes = enum_reg<std::equal_to<>, arch::write, const operand>();
			for ( auto wr : writes )
			{
				if ( rw.base == wr->reg.base &&
					 !( rw.get_mask() & ( ~wr->reg.get_mask() ) ) )
					return wr;
			}
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
