#pragma once
#include <stdint.h>
#include "logger.hpp"

namespace vtil::assert
{
	static void or_die( bool condition, const char* file_name, const char* condition_str, uint32_t line_number )
	{
		if ( condition ) return;
		logger::error
		(
			"Assertion failure at %s:%d (%s)",
			file_name,
			line_number,
			condition_str
		);
	}
};

#define fassert__stringify(x) #x
#define fassert(x) vtil::assert::or_die( (x), __FILE__, fassert__stringify(x), __LINE__ )
#define unreachable() vtil::logger::error("")