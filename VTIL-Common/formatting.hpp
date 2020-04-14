#pragma once
#include <string>
#include <type_traits>

#define FMT_TEMP_REG	"t%d"
#define FMT_INS_MNM		"%-8s"
#define FMT_INS_OPR		"%-12s"
#define FMT_INS			FMT_INS_MNM " " FMT_INS_OPR " " FMT_INS_OPR " " FMT_INS_OPR " " FMT_INS_OPR

namespace vtil::format
{
	// Suffixes used to indicate registers of N bytes.
	//
	static constexpr char suffix_map[] = { ' ', 'b', 'w', ' ', 'd', ' ', ' ', ' ', 'q' };

	// Used to fix std::string usage in combination with "%s".
	//
	template<typename T>
	__forceinline static auto fix_parameter( T&& x )
	{
		if constexpr ( std::is_same_v<std::remove_cvref_t<T>, std::string> || std::is_same_v<std::remove_cvref_t<T>, std::wstring> )
			return x.data();
		else
			return std::forward<T>( x );
	}

	// Returns formatted string according to <fms>.
	//
	template<typename... params>
	static std::string str( const char* fmt, params&&... ps )
	{
		char buffer[ 512 ];
		sprintf_s( buffer, fmt, fix_parameter<params>( std::forward<params>( ps ) )... );
		return buffer;
	}

	// Formats the integer into a signed hexadecimal.
	//
	template<typename T, std::enable_if_t<std::is_integral_v<std::remove_cvref_t<T>>, int> = 0>
	static std::string hex( T&& value )
	{
		if ( !std::is_signed_v<std::remove_cvref_t<T>> || value >= 0 )
			return str( "0x%llx", value );
		else
			return str( "-0x%llx", -value );
	}

	// Formats the integer into a signed hexadecimal with explicit + if positive.
	//
	inline static std::string offset( int64_t value )
	{
		if ( value >= 0 )
			return str( "+ 0x%llx", value );
		else
			return str( "- 0x%llx", -value );
	}
};