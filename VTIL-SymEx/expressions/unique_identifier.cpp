#include "unique_identifier.hpp"

namespace vtil::symbolic
{
	// Conversion to human-readable format.
	// - Note: Will cache the return value in string_cast as lambda capture if non-const-qualified.
	//
	std::string unique_identifier::to_string()
	{
		if ( !value )
			return "null";
		std::string str = string_cast( value );
		string_cast = [ str ] ( auto& ) { return str; };
		return str;
	}
	std::string unique_identifier::to_string() const
	{
		if ( !value )
			return "null";
		return string_cast( value );
	}

	// Simple comparison operators.
	//
	bool unique_identifier::operator==( const unique_identifier& o ) const
	{
		// If any of the sides do not have a value, return false.
		//
		if ( !value || !o.value )
			return false;

		// If hash mismatch, return false.
		//
		if ( hash != o.hash )
			return false;

		// Assert internal equivalance.
		//
		return compare_value ? compare_value( value, o.value ) == 0 : true;
	}
	bool unique_identifier::operator<( const unique_identifier& o ) const
	{
		// Consider null side less.
		//
		if ( !value && o.value ) return true;
		if ( value && !o.value ) return false;

		// Compare by hash first.
		//
		if ( hash != o.hash )
			return hash < o.hash;

		// Compare internals if equivalent hash.
		//
		return compare_value ? compare_value( value, o.value ) < 0 : false;
	}
};
