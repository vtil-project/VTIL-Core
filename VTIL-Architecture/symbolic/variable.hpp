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
		std::wstring name;

		// Origin of the variable if relevant.
		//
		ilstream_const_iterator origin = {};
		int operand_index;

		// Default constructors.
		//
		unique_identifier() {}
		unique_identifier( const std::string& name ) : name( utf_cvt_t{}.from_bytes( name ) ) { fassert( is_valid() ); }
		unique_identifier( const std::wstring& name ) : name( name ) { fassert( is_valid() ); }
		
		// Constructor for unique identifier created from stream iterator.
		//
		unique_identifier( ilstream_iterator origin, int operand_index ) : operand_index( operand_index ), origin( origin )
		{
			if ( origin->base == &ins::str )
			{
				fassert( origin->operands[ 0 ].reg == X86_REG_RSP );
				int64_t stack_offset = origin->operands[ 1 ].i64;
				name = stack_offset >= 0 ? L"arg" : L"var";
				name += format::suffix_map[ origin->access_size() ];
				name += utf_cvt_t{}.from_bytes( format::hex( abs( stack_offset ) ) );
			}
			else
			{
				fassert( origin->operands[ operand_index ].is_register() );
				fassert( origin->base->access_types[ operand_index ] >= arch::write );
				name = utf_cvt_t{}.from_bytes( origin->operands[ operand_index ].reg.to_string() );
			}
		}
	
		// Returns whether the unique identifier is valid or not.
		//
		bool is_valid() const { return name.size() && !iswdigit( name[ 0 ] ); }

		// Returns whether this is a reserved identifier or not.
		//
		bool is_reserved() const { return name.size() == 1 && uid_reserved_dictionary.find( name[ 0 ] ) != std::wstring::npos; }

		// Conversion to UTF-8.
		//
		std::string to_string() const { return utf_cvt_t{}.to_bytes( name ); }
	
		// Simple comparison operators.
		//																										v-- Blame intel compiler.
		bool operator==( const unique_identifier& o ) const { return name.size() == o.name.size() && !memcmp( name.data(), o.name.data(), name.size() * sizeof( wchar_t ) ); /*name == o.name*/; }
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
		variable( const std::string& uid, uint8_t size ) : size( size ), uid( uid ) { fassert( is_valid() ); }
		variable( const std::wstring& uid, uint8_t size ) : size( size ), uid( uid ) { fassert( is_valid() ); }
		variable( ilstream_iterator origin, int operand_index ) : size( origin->access_size()), uid( origin, operand_index ){ fassert( is_valid() ); }

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

		// Getter for value:
		//
		template<bool sign_extend = false>
		auto get( uint8_t new_size ) const
		{
			// If size does not match, new size:
			//
			uint64_t value_out = u64;
			if ( new_size != size )
			{
				// Sign extend to 64-bit first
				//
				if ( sign_extend )
				{
					uint64_t sign_mask = 1ull << ( ( size ? size : 8 ) * 8 - 1 );
					uint64_t value_mask = sign_mask - 1;

					uint64_t extended_bits = ( u64 & sign_mask ) ? ~0ull : 0ull;
					extended_bits &= ~value_mask;
					value_out = extended_bits | ( u64 & value_mask );
				}

				// Mask the value if size is specified.
				//
				if ( new_size )
					value_out &= ~0ull >> ( 64 - new_size * 8 );
			}
			
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
		bool operator<( const variable& o ) const { return to_string() < o.to_string(); }
	};
};