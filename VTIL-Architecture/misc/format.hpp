#pragma once
#include <string>
#include <type_traits>
#include <platform.h>


#define FMT_TEMP_REG	"t%d"
#define FMT_INS_MNM		"%-8s"
#define FMT_INS_OPR		"%-12s"
#define FMT_INS			FMT_INS_MNM " " FMT_INS_OPR " " FMT_INS_OPR " " FMT_INS_OPR " " FMT_INS_OPR
					 
namespace vtil::format
{
	static constexpr char suffix_map[] = { ' ', 'b', 'w', ' ', 'd', ' ', ' ', ' ', 'q' };

	template<typename... params>
	static std::string str( const char* fmt, params... ps )
	{
		char buffer[ 512 ];
		sprintf_s( buffer, fmt, io::fix_format_paramter( ps )... );
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