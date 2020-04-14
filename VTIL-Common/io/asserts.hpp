#pragma once
#include <stdint.h>
#include "logger.hpp"

namespace vtil::logger
{
	static void assert_helper( bool condition, const char* file_name, const char* condition_str, uint32_t line_number )
	{
		if ( condition ) return;
		error
		(
			"Assertion failure at %s:%d (%s)",
			file_name,
			line_number,
			condition_str
		);
	}
};

#define fassert__stringify(x) #x
#define fassert(x) vtil::logger::assert_helper( (x), __FILE__, fassert__stringify(x), __LINE__ )
#define unreachable() fassert( false )