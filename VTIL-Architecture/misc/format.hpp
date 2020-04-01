#pragma once
#include <string>
#include <type_traits>

#define FMT_TEMP_REG	"t%d"
#define FMT_INS_MNM		"%-8s"
#define FMT_INS_OPR		"%-12s"
#define FMT_INS			FMT_INS_MNM " " FMT_INS_OPR " " FMT_INS_OPR " " FMT_INS_OPR " " FMT_INS_OPR
					 
namespace vtil::format
{
	static constexpr char suffix_map[] = { ' ', 'b', 'w', ' ', 'd', ' ', ' ', ' ', 'q' };

	template<typename T>
	__forceinline static auto fix_format_paramter( const T& x )
	{
		if constexpr ( std::is_same_v<T, std::string> ||
					   std::is_same_v<T, std::wstring> )
			return x.data();
		else
			return x;
	}

	template<typename... params>
	static std::string str( const char* fmt, params... ps )
	{
		char buffer[ 512 ];
		sprintf_s( buffer, fmt, fix_format_paramter( ps )... );
		return buffer;
	}

	template<typename T>
	static std::string hex( T value )
	{
		if ( !std::is_signed_v<T> || value >= 0 )
			return str( "0x%llx", value );
		else
			return str( "-0x%llx", -value );
	}

	static std::string offset( int64_t value )
	{
		if ( value >= 0 )
			return str( "+ 0x%llx", value );
		else
			return str( "- 0x%llx", -value );
	}
};