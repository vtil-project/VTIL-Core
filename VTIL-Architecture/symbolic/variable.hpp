#pragma once
#include <string>
#include <codecvt>
#include <type_traits>
#include "..\arch\operands.hpp"
#include "..\arch\instruction_set.hpp"
#include "..\routine\basic_block.hpp"
#include "..\misc\format.hpp"

namespace vtil::symbolic
{
	// Dictionary for the names of reserved unique identifiers. (For simplifier)
	//
	static const std::wstring uid_reserved_dictionary =
		L"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρστυφχψω"
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	// Unique identifier for a variable.
	//
	struct unique_identifier
	{
		// Conversion between the internal unicode type and the UTF8 output expected.
		//
		using utf_cvt_t = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>;

		// Unique name of the variable.
		//
		std::string name;

		// Origin of the variable if relevant.
		//
		int operand_index;
		ilstream_const_iterator origin = {};
		std::optional<int32_t> stack_id;
		std::optional<register_view> register_id = {};

		// Default constructors.
		//
		unique_identifier() {}
		unique_identifier( const std::string& name ) : name( name ) { fassert( is_valid() ); }
		unique_identifier( const std::wstring& name ) : name( utf_cvt_t{}.to_bytes( name ) ) { fassert( is_valid() ); }
		
		// Constructor for unique identifier created from stream iterator.
		//
		unique_identifier( ilstream_const_iterator origin, int operand_index ) : operand_index( operand_index ), origin( origin )
		{
			// Identifier for memory:
			//
			if ( operand_index == -1 )
			{
				// TODO: Handle external memory?
				auto [mem_base, mem_off] = origin->get_mem_loc();
				fassert( origin->base->accesses_memory() );
				fassert( mem_base.base == X86_REG_RSP );
				stack_id = { mem_off };
			}
			// Identifier for register/temporary:
			//
			else
			{
				fassert( origin->operands[ operand_index ].is_register() );
				register_id = { origin->operands[ operand_index ].reg };
			}
			refresh();
		}

		// Refreshes the unique identifier if it's bound to a register value or a stack variable.
		//
		unique_identifier& refresh()
		{
			if ( register_id.has_value() )
			{
				name = register_id->to_string();

				name += '#';
				name += format::hex( origin->vip );
			}
			else if( stack_id.has_value() )
			{
				name = stack_id.value() >= 0 ? "arg" : "var";
				name += format::suffix_map[ origin->access_size() ];
				name += format::hex( abs( stack_id.value() ) );


				name += '#';
				name += format::hex( origin->vip );

			}
			return *this;
		}
	
		// Returns whether the unique identifier is valid or not.
		//
		bool is_valid() const { return name.size() && !iswdigit( name[ 0 ] ); }

		// Returns whether this is a reserved identifier or not.
		//
		bool is_reserved() const { return name.size() == 1 && uid_reserved_dictionary.find( name[ 0 ] ) != std::wstring::npos; }

		// Returns whether this is a value off of stack that is acting as a symbolic variable.
		//
		bool is_stack() const { return is_valid() && stack_id.has_value(); }
		
		// Returns whether this is a value of a register that is acting as a symbolic variable.
		//
		bool is_register() const { return is_valid() && register_id.has_value(); }
		
		// Returns the stack pointer associated with the variable.
		//
		int32_t get_sp() const
		{
			fassert( is_stack() );
			return stack_id.value();
		}

		// Returns the register that is associated with the variable.
		//
		register_view get_reg() const
		{
			fassert( is_register() );
			return register_id.value();
		}

		// Conversion to UTF-8.
		//
		std::string to_string() const { return name; }
	
		// Simple comparison operators.
		//
		bool operator==( const unique_identifier& o ) const { return name.size() == o.name.size() && name == o.name; }
		bool operator<( const unique_identifier& o ) const { return name < o.name; }
		bool operator!=( const unique_identifier& o ) const { return name != o.name; }
	};


	// Describes a variable that will be used in a symbolic expression.
	//
	struct variable
	{
		// A unique identifier for the variable, if left empty
		// this variable will be treated as a constant value.
		//
		unique_identifier uid;

		// If constant, the value that is being represented
		// by this variable.
		//
		union
		{
			uint64_t u64;
			int64_t i64;
		};

		// Size of the variable, used for both constants and UID-bound variables.
		// - If zero implies any size.
		//
		uint8_t size;

		// Default constructor, will make an invalid varaible.
		//
		variable() : size( 0 ) {}

		// Constructor for uniquely variables.
		//
		variable( const std::string& uid, uint8_t size ) : uid( uid ), size( size ) { fassert( is_valid() ); }
		variable( const std::wstring& uid, uint8_t size ) : uid( uid ), size( size ) { fassert( is_valid() ); }
		variable( ilstream_const_iterator origin, int operand_index )
		{ 
			// If operand is an immediate or a register:
			//
			if ( operand_index != -1 )
			{
				// If immediate, assign constant:
				//
				if ( origin->operands[ operand_index ].is_immediate() )
					u64 = origin->operands[ operand_index ].u64;
				// If register, generate unique identifier:
				//
				else
					uid = { origin, operand_index };

				// Assing operand size as the variable size.
				//
				size = origin->operands[ operand_index ].size();
			}
			// If operand is a stack pointer:
			//
			else
			{
				// Generate a unique identifier and assign the size.
				//
				uid = { origin, operand_index };
				size = origin->access_size();
			}
			
			fassert( is_valid() ); 
		}

		// Constructor for variables that represent constant values.
		//
		template<typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
		variable( T imm, uint8_t size = sizeof( T ) ) : size( size )
		{
			fassert( is_valid() ); 

			// If a signed type was passed, sign extend, otherwise zero extend before storing.
			//
			if constexpr ( std::is_signed_v<T> )
				i64 = imm;
			else
				u64 = imm;
		}

		// Simple helpers to determine the type of the variable.
		//
		bool is_valid() const { return size == 0 || size == 1 || size == 2 || size == 4 || size == 8; }
		bool is_symbolic() const { return uid.is_valid(); }
		bool is_constant() const { return !uid.is_valid(); }

		// Wrappers around unique_identifer:: helpers used to resolve the actual operand being traced.
		//
		bool is_stack() const { return uid.is_stack(); }
		bool is_register() const { return uid.is_register(); }
		bool is_arbitrary() const { return uid.is_valid() && !uid.origin.is_valid(); }
		int32_t get_sp() const { return uid.get_sp(); }
		register_view get_reg() const { register_view reg = uid.get_reg(); fassert( size == reg.size ); return reg; }

		// Getter for value:
		//
		template<bool sign_extend = false>
		auto get( uint8_t new_size ) const
		{
			uint64_t value_out = u64;
			if ( size ) value_out &= ~0ull >> ( 64 - size * 8 );

			// Sign extend to 64-bit first
			//
			if ( sign_extend )
			{
				uint64_t sign_mask = 1ull << ( ( size ? size : 8 ) * 8 - 1 );
				uint64_t value_mask = sign_mask - 1;

				uint64_t extended_bits = ( value_out & sign_mask ) ? ~0ull : 0ull;
				extended_bits &= ~value_mask;
				value_out = extended_bits | ( value_out & value_mask );
			}

			// Mask the value if size is specified.
			//
			if ( new_size )
				value_out &= ~0ull >> ( 64 - new_size * 8 );
			
			// Return the value either sign extended or zero extended.
			//
			if constexpr ( sign_extend )
				return int64_t( value_out );
			else
				return uint64_t( value_out );
		}

		// Converts the variable into human-readable format.
		//
		std::string to_string() const
		{
			return is_symbolic() ? uid.to_string() : format::hex( i64 );
		}

		// Basic comparison operators.
		//
		bool operator==( const variable& o ) const { return uid == o.uid && ( is_symbolic() || ( size && o.size ? size == o.size && u64 == o.u64 : i64 == o.i64 ) ); }
		bool operator!=( const variable& o ) const { return !operator==( o ); }
		bool operator<( const variable& o ) const 
		{ 
			if ( is_symbolic() != o.is_symbolic() )
				return o.is_symbolic();

			if ( is_symbolic() )
				return uid < o.uid;
			else
				return u64 < o.u64;
		}
	};
};