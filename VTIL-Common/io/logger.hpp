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
#include <functional>
#include "formatting.hpp"

// If inline assembly is supported use it, otherwise rely on intrinsics to emit INT3.
//
#ifdef _MSC_VER
	#include <intrin.h>
#else
	#define __debugbreak() __asm__ volatile( "int $3" )
#endif

// [Configuration]
// Determine which file stream we should use for logging.
//
#ifndef VTIL_LOGGER_DST
	#define VTIL_LOGGER_DST stdout
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

	namespace impl
	{
		// Used to mark functions noreturn.
		//
		static void noreturn_helper [[noreturn]] () { __debugbreak(); abort(); }
	};

	// Describes the state of the logging engine.
	//
	struct state
	{
		// Lock of the stream.
		//
		std::recursive_mutex lock;

		// Whether prints are muted or not.
		//
		bool mute = false;

		// Current padding level.
		//
		int padding = -1;

		// Padding leftover from previous print.
		//
		int padding_carry = 0;

		// Whether stdout was initialized or not.
		//
		bool initialized = false;

		// Gets the global logger state.
		//
		static state* get();
	};

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
			state::get()->lock.lock();
			prev = state::get()->padding;
			state::get()->padding += u;
			state::get()->lock.unlock();
		}

		void end()
		{
			if ( active-- <= 0 ) return;
			state::get()->lock.lock();
			state::get()->padding = prev;
			state::get()->lock.unlock();
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
			state::get()->lock.lock();
			prev = state::get()->mute;
			state::get()->mute |= !verbose_output;
			state::get()->lock.unlock();
		}

		void end()
		{
			if ( active-- <= 0 ) return;
			state::get()->lock.lock();
			state::get()->mute = prev;
			state::get()->lock.unlock();
		}
		~scope_verbosity() { end(); }
	};

	// Main function used when logging.
	//
	template<typename... params>
	static int log( console_color color, const char* fmt, params&&... ps )
	{
		auto state = state::get();

		// Hold the lock for the critical section guarding ::log.
		//
		std::lock_guard g( state->lock );

		// Do not execute if logs are disabled.
		//
		if ( state->mute ) return 0;

		// If we should pad this output:
		//
		int out_cnt = 0;
		if ( state->padding > 0 )
		{
			// If it was not carried from previous:
			//
			if ( int pad_by = state->padding - state->padding_carry )
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
				state->padding_carry = 0;
			else
				state->padding_carry = state->padding;
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

		// Acquire the lock.
		//
		std::lock_guard _g{ state::get()->lock };
		
		// Reset padding.
		//
		int old_padding = state::get()->padding;
		state::get()->padding = 0;

		// Print the warning.
		//
		log( CON_YLW, "[!] Warning: %s\n", message );

		// Restore the padding and return.
		//
		state::get()->padding = old_padding;
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

		// Error will stop any execution so feel free to ignore any locks. Print error message.
		//
		set_color( CON_RED );
		fprintf( VTIL_LOGGER_DST, "[*] Error: %s\n", message.c_str() );

		// Break the program. 
		//
		impl::noreturn_helper();
	}
};
