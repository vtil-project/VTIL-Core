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
#if _WIN64
	#define _CRT_SECURE_NO_WARNINGS
	#define WIN32_LEAN_AND_MEAN
	#define NOMINMAX
	#include <Windows.h>
#endif
#include "logger.hpp"
#include <cstdlib>

namespace vtil::logger
{
	// Global logger state.
	//
	logger_state_t::logger_state_t()
	{
#if _WIN64
		SetConsoleOutputCP( CP_UTF8 );
		ansi_escape_codes = std::getenv( "GITLAB_CI" ) != nullptr;
#endif
	}

	// Changes color where possible.
	//
	void set_color( console_color color )
	{
		if ( logger_state.ansi_escape_codes )
		{
			switch ( color )
			{
				case CON_BRG: printf( "\x1b[37m" ); break;
				case CON_YLW: printf( "\x1b[33m" ); break;
				case CON_PRP: printf( "\x1b[35m" ); break;
				case CON_RED: printf( "\x1b[31m" ); break;
				case CON_CYN: printf( "\x1b[36m" ); break;
				case CON_GRN: printf( "\x1b[32m" ); break;
				case CON_BLU: printf( "\x1b[34m" ); break;
				case CON_DEF:
				default:      printf( "\x1b[0m" );  break;
			}
		}
#if _WIN64
		else
		{
			SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), color );
		}
#endif
	}
};