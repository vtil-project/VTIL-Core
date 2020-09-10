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
#include "type_helpers.hpp"

namespace vtil
{
	namespace impl
	{
		template<typename T>
		concept HasIncDec = requires( T x ){ x++; x--; };
	};

	// Implements a simple RAII style scope-deferred task.
	//
	template<typename T> requires Invocable<T, void>
	struct finally
	{
		T functor;
		bool set = true;
		finally( T&& fn ) : functor( std::forward<T>( fn ) ) {}
		finally( finally&& o ) : functor( o.functor ), set( std::exchange( o.set, false ) ) {}
		finally( const finally& ) = delete;
		~finally() { if( set ) functor(); }
	};

	// Commonly used guard for the counter increment/decrement.
	//
	template<impl::HasIncDec T>
	struct counter_guard
	{
		T& ref;
		counter_guard( T& ref ) : ref( ref ) { ref++; }
		counter_guard( const counter_guard& ) = delete;
		~counter_guard() { ref--; }
	};
};