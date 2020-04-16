// Copyright (c) 2020 Can Bölük and contributors of the VTIL Project		   
// All rights reserved.														   
// 																			   
// Redistribution and use in source and binary forms, with or without		   
// modification, are permitted provided that the following conditions are met: 
// 																			   
// 1. Redistributions of source code must retain the above copyright notice,   
//    this list of conditions and the following disclaimer.					   
// 2. Redistributions in binary form must reproduce the above copyright		   
//    notice, this list of conditions and the following disclaimer in the	   
//    documentation and/or other materials provided with the distribution.	   
// 3. Neither the name of mosquitto nor the names of its					   
//    contributors may be used to endorse or promote products derived from	   
//    this software without specific prior written permission.				   
// 																			   
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE	   
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR		   
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF		   
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS	   
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN	   
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)	   
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  
// POSSIBILITY OF SUCH DAMAGE. 											       
//
// Furthermode, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information				      |
// |-------------------------|------------------------------------------------|
// | amd64/*                 | https://github.com/aquynh/capstone/		      |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#pragma once
#include <iostream>
#include <stdint.h>
#include <string>
#include <mutex>
#include <intrin.h>
#include "formatting.hpp"

namespace vtil::logger
{
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

	// State of the logging engine.
	//
	static std::mutex log_mutex;
	static bool log_init = false;
	static bool log_disable = false;

	// Padding customization for logger.
	//
	static constexpr char log_padding_c = '|';
	static constexpr uint32_t log_padding_step = 4;

	// Current logger padding.
	//
	static int log_padding = -1;
	static int log_padding_carry = 0;

	// RAII hacks for setting scope padding and verbosity.
	//
	struct scope_padding
	{
		uint32_t prev = 0;
		inline scope_padding( unsigned u )
		{
			prev = log_padding;
			log_padding += u;
		}

		inline void end()
		{
			log_padding = prev;
		}
		inline ~scope_padding() { end(); }
	};
	struct scope_verbosity
	{
		bool prev = 0;
		scope_verbosity( bool b )
		{
			prev = log_disable;
			log_disable |= !b;
		}

		inline void end()
		{
			log_disable = prev;
		}
		inline ~scope_verbosity() { end(); }
	};

	// Implementation details.
	//
	namespace impl
	{
		// Internally used to change the console if possible.
		//
		void set_color( console_color color );

		// Internally used to initialize the logger.
		//
		void initialize();
	
		// Used to mark functions noreturn.
		//
		__declspec( noreturn ) __forceinline static void noreturn_helper() { __debugbreak(); noreturn_helper(); }
	};

	// Main function used when logging.
	//
	template<console_color color = CON_DEF, typename... params>
	static int log( const char* fmt, params&&... ps )
	{
		// Do not execute if logs are disabled.
		//
		if ( log_disable ) return 0;

		// Acquire the logging mutex.
		//
		std::lock_guard g( log_mutex );

		// Initialize logger if not done already.
		//
		impl::initialize();

		// Set to defualt color.
		//
		impl::set_color( CON_DEF );
		int out_cnt = 0;

		// If we should pad this output:
		//
		if ( log_padding > 0 )
		{
			// If it was not carried from previous:
			//
			if( int pad_by = log_padding - log_padding_carry )
			{
				for ( int i = 0; i < pad_by; i++ )
				{
					if ( ( i + 1 ) == pad_by )
					{
						out_cnt += printf( "%*c", log_padding_step - 1, ' ' );
						if ( fmt[ 0 ] == ' ' ) putchar( log_padding_c );
					}
					else
					{
						out_cnt += printf( "%*c%c", log_padding_step - 1, ' ', log_padding_c );
					}
				}
			}

			// Set or clear the carry for next.
			//
			if ( fmt[ strlen( fmt ) - 1 ] == '\n' )
				log_padding_carry = 0;
			else
				log_padding_carry = log_padding;
		}

		// Set to requested color and redirect to printf.
		//
		impl::set_color( color );
		return out_cnt + printf( fmt, vtil::format::fix_parameter<params>( std::forward<params>( ps ) )... );
	}

	// Prints an error message and breaks the execution.
	//
	template<typename... params>
	__declspec( noreturn ) static void error( const char* fmt, params&&... ps )
	{
		log<CON_RED>( fmt, std::forward<params>( ps )... );

#ifdef _DEBUG
		__debugbreak();
#else
		exit( 1 );
#endif
		impl::noreturn_helper();
	}
};