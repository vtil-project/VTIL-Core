// Copyright (c) 2020 Can Boluk and contributors of the VTIL Project   
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
// 3. Neither the name of VTIL Project nor the names of its contributors
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.   
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
#pragma once
#include <iostream>
#include <stdint.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <mutex>
#include <thread>
#include <functional>
#include "formatting.hpp"
#include "../util/intrinsics.hpp"
#include "../util/literals.hpp"

// [Configuration]
// Determine which file stream we should use for logging/errors and whether to 
// catch unhandled exceptions or not.
//
#ifndef VTIL_CATCH_UNHANDLED
	#define VTIL_CATCH_UNHANDLED 1
#endif
#ifndef VTIL_LOGGER_DST
	#define VTIL_LOGGER_DST stdout
#endif
#ifndef VTIL_LOGGER_ERR_DST
	#define VTIL_LOGGER_ERR_DST stderr
#endif

namespace vtil::logger
{
	// Padding customization for logger.
	//
	static constexpr char log_padding_c = '|';
	static constexpr int log_padding_step = 2;

	// Console colors, only used on Windows platform.
	//
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

	// Describes the state of the logging engine.
	//
	struct logger_state_t
	{
		// Lock of the stream.
		//
		std::recursive_mutex mtx;

		// Whether prints are muted or not.
		//
		bool mute = false;

		// Current padding level.
		//
		int padding = -1;

		// Padding leftover from previous print.
		//
		int padding_carry = 0;

		// Whether to use ANSI escape codes or Windows console API for colors.
		// Defaults to false on Windows, unless in a Gitlab CI environment.
		//
		bool ansi_escape_codes = true;

		// Constructor initializes logger.
		//
		logger_state_t();

		// Wrap around the lock.
		//
		void lock() { mtx.lock(); }
		void unlock() { mtx.unlock(); }
		bool try_lock() { return mtx.try_lock(); }
		bool try_lock( timeunit_t max_wait )
		{
			bool locked = false;
			auto t0 = time::now();
			while ( !( locked = try_lock() ) )
				if ( ( time::now() - t0 ) > max_wait )
					break;
			return locked;
		}
	};
	inline logger_state_t logger_state = {};

	// Changes color where possible.
	//
	void set_color( console_color color );

	// RAII hack for incrementing the padding until routine ends.
	// Can be used with the argument u=0 to act as a lock guard.
	// - Will wait for the critical section ownership and hold it
	//   until the scope ends.
	//
	struct scope_padding
	{
		int active;
		int prev;

		scope_padding( unsigned u ) : active( 1 )
		{
			logger_state.lock();
			prev = logger_state.padding;
			logger_state.padding += u;
		}

		void end()
		{
			if ( active-- <= 0 ) return;
			logger_state.padding = prev;
			logger_state.unlock();
		}
		~scope_padding() { end(); }
	};

	// RAII hack for changing verbosity of logs within the scope.
	// - Will wait for the critical section ownership and hold it
	//   until the scope ends.
	//
	struct scope_verbosity
	{
		int active;
		bool prev;

		scope_verbosity( bool verbose_output ) : active( 1 )
		{
			logger_state.lock();
			prev = logger_state.mute;
			logger_state.mute |= !verbose_output;
		}

		void end()
		{
			if ( active-- <= 0 ) return;
			logger_state.mute = prev;
			logger_state.unlock();
		}
		~scope_verbosity() { end(); }
	};

	// Main function used when logging.
	//
	template<typename... params>
	static int log( console_color color, const char* fmt, params&&... ps )
	{
		// Hold the lock for the critical section guarding ::log.
		//
		std::lock_guard g( logger_state );

		// Do not execute if logs are disabled.
		//
		if ( logger_state.mute ) return 0;

		// If we should pad this output:
		//
		int out_cnt = 0;
		if ( logger_state.padding > 0 )
		{
			// If it was not carried from previous:
			//
			if ( int pad_by = logger_state.padding - logger_state.padding_carry )
			{
				for ( int i = 0; i < pad_by; i++ )
				{
					if ( ( i + 1 ) == pad_by )
					{
						out_cnt += fprintf( VTIL_LOGGER_DST, "%*c", log_padding_step - 1, ' ' );
						if ( fmt[ 0 ] == ' ' ) putchar( log_padding_c );
					}
					else
					{
						out_cnt += fprintf( VTIL_LOGGER_DST, "%*c%c", log_padding_step - 1, ' ', log_padding_c );
					}
				}
			}

			// Set or clear the carry for next.
			//
			if ( fmt[ strlen( fmt ) - 1 ] == '\n' )
				logger_state.padding_carry = 0;
			else
				logger_state.padding_carry = logger_state.padding;
		}

		// Set to requested color and redirect to printf.
		//
		set_color( color );

		// If string literal with no parameters, use puts instead.
		//
		if ( sizeof...( ps ) == 0 )
			out_cnt += fputs( fmt, VTIL_LOGGER_DST );
		else
			out_cnt += fprintf( VTIL_LOGGER_DST, fmt, format::fix_parameter<params>( std::forward<params>( ps ) )... );

		// Reset to defualt color.
		//
		set_color( CON_DEF );
		return out_cnt;
	}
	template<console_color color = CON_DEF, typename... params>
	static int log( const char* fmt, params&&... ps )
	{
		return log( color, fmt, std::forward<params>( ps )... );
	}

	// Prints a warning message.
	//
	template<typename... params>
	static void warning( const char* fmt, params&&... ps )
	{
		// Format warning message.
		//
		std::string message = format::str(
			fmt,
			format::fix_parameter<params>( std::forward<params>( ps ) )...
		);

		// Try acquiring the lock.
		//
		bool locked = logger_state.try_lock( 100ms );
		
		// Print the warning.
		//
		set_color( CON_YLW );
		fprintf( VTIL_LOGGER_ERR_DST, "\n[!] Warning: %s\n", message.c_str() );

		// Unlock if previously locked.
		//
		if ( locked ) logger_state.unlock();
	}

	// Allows to place a hook onto the error function, this is mainly used for
	// the python project to avoid crasing the process.
	//
	inline std::function<void( const std::string& )> error_hook;

	// Prints an error message and breaks the execution.
	//
	template<typename... params>
	static void error [[noreturn]] ( const char* fmt, params&&... ps )
	{
		// Format error message.
		//
		std::string message = format::str(
			fmt,
			format::fix_parameter<params>( std::forward<params>( ps ) )...
		);

		// If there is an active hook, call into it.
		//
		if ( error_hook ) error_hook( message );

		// Try acquiring the lock.
		//
		bool locked = logger_state.try_lock( 100ms );

		// Print the error message.
		//
		set_color( CON_RED );
		fprintf( VTIL_LOGGER_ERR_DST, "\n[*] Error: %s\n", message.c_str() );

		// Break the program, leave the logger locked since we'll break anyways.
		//
		unreachable();
	}

#if VTIL_CATCH_UNHANDLED
	// Set default terminate handler.
	//
	namespace impl
	{
		inline const std::terminate_handler prev_terminate_handler = std::set_terminate( [ ] ()
		{
			// If there is a pending C++ exception, print it.
			//
			try { throw; }
			catch ( const std::exception& e ) 
			{
				// Same as ::error logic, but do not terminate nor redirect to hook.
				//
				std::string message = format::as_string( e );
				set_color( CON_RED );
				fprintf( VTIL_LOGGER_ERR_DST, "\n[*] Error: %s\n", message.c_str() );
				sleep_for( 1000ms );
			}
			catch ( ... ) {}

			// Call into previous handler if relevant.
			//
			if ( prev_terminate_handler ) 
				prev_terminate_handler();
		} );
	};
#endif
};
