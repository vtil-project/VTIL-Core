#include "logger.hpp"

#if _WIN64
	#define WIN32_LEAN_AND_MEAN
	#define NOMINMAX
	#include <Windows.h>
#endif

namespace  vtil::logger::impl
{
	// Internally used to change the console if possible.
	//
	void set_color( console_color color )
	{
#if _WIN64
		SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), color );
#endif
	}

	// Internally used to initialize the logger.
	//
	void initialize()
	{
		if ( log_init ) return;
#if _WIN64
		SetConsoleOutputCP( CP_UTF8 );
#endif
		log_init = true;
	}
};