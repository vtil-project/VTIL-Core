#pragma once

#if _WIN64
	#include <Windows.h>
#else
	#include <sys/mman.h>
#endif

#include <iostream>
#include <stdint.h>
#include <string>
#include <fstream>
#include <vector>
#include <mutex>
#undef min
#undef max

enum console_color
{
	CON_BRG = 15,
	CON_YLW = 14,
	CON_PRP = 13,
	CON_RED = 12,
	CON_CYN = 11,
	CON_GRN = 10,
	CON_BLU = 9,
	CON_DEF = 7,
};

namespace mem
{
	static void* allocate_rwx( size_t size )
	{
#if _WIN64
		return VirtualAlloc( 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
#else
		return mmap( 0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
#endif
	}

	static void free_rwx( void* pointer, size_t size )
	{
#if _WIN64
		VirtualFree( pointer, 0, MEM_FREE | MEM_RELEASE );
#else
		mmunmap( pointer, size );
#endif
	}
};

namespace io
{
	template<bool critical = false>
	static void bp() 
	{ 
#ifdef _DEBUG
		__asm { int 3 };
#else
		if constexpr ( critical )
			exit( -1 );
#endif
	}

	static int log_padding = 0;
	static std::mutex print_mutex;
	static bool log_init = false;

	template<typename T>
	__forceinline static auto fix_format_paramter( const T& x )
	{
		if constexpr ( std::is_same_v<T, std::string> ||
					   std::is_same_v<T, std::wstring> )
			return x.data();
		else
			return x;
	}

	template<console_color color = CON_DEF, typename... params>
	static int log( const char* fmt, params&&... ps )
	{
		std::lock_guard g( print_mutex );
#if _WIN64
		SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), color );
		if ( !log_init )
		{
			SetConsoleOutputCP( CP_UTF8 );
			log_init = true;
		}
#endif
		int v = printf( fmt, fix_format_paramter( ps )... );
		if ( fmt[ strlen( fmt ) - 1 ] == '\n' && log_padding > 0 )
			v += printf( "%*c", log_padding * 8, ' ' );
		return v;
	}

	template<bool critical = true, typename... params>
	static void error( const char* fmt, params&&... ps )
	{
		log<CON_RED>( fmt, std::forward<params>( ps )... );
		bp<critical>();
	}

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

	static std::vector<uint8_t> read_raw( const std::wstring& file_path )
	{
		// Try to open file as binary
		std::ifstream file( file_path, std::ios::binary );
		if ( !file.good() ) throw "Input file cannot be opened.";

		// Read the whole file
		std::vector<uint8_t> bytes = std::vector<uint8_t>( std::istreambuf_iterator<char>( file ), {} );
		if ( bytes.size() == 0 ) throw "Input file is empty.";
		return bytes;
	}

	static void write_raw( void* data, size_t size, const std::wstring& file_path )
	{
		std::ofstream file( file_path, std::ios::binary );
		if ( !file.good() ) throw "Output file cannot be opened.";
		file.write( ( char* ) data, size );
	}
};

#define fassert__stringify(x) #x
#define fassert(...) io::assert_helper( (__VA_ARGS__), __FILE__, fassert__stringify(__VA_ARGS__), __LINE__ )
#define unreachable() fassert( false )