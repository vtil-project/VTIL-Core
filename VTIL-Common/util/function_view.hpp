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
#include "../io/asserts.hpp"

namespace vtil
{
	// Declares a light-weight std::function replacement.
	// - Note: will not copy the lambda objects, lifetime is left to the user.
	//
	template<typename F>
	struct function_view;
	template<typename Ret, typename... Args>
	struct function_view<Ret( Args... )>
	{
		// Hold object pointer, invocation wrapper and whether it is const qualified or not.
		//
		void* obj = nullptr;
		Ret( *fn )( void*, Args... ) = nullptr;
		bool const_invocable = true;

		// Null construction.
		//
		function_view() {}
		function_view( std::nullptr_t ) {}

		// Construct from any functor.
		//
		template<typename F> requires ( Invocable<F, Ret, Args...> && ( !Same<std::decay_t<F>, function_view> ) )
		function_view( F& functor )
		{
			obj = ( void* ) &functor;
			fn = [ ] ( void* obj, Args... args ) -> Ret
			{
				return ( *( F* ) obj )( std::forward<Args>( args )... );
			};
			const_invocable = Invocable<std::add_const_t<std::decay_t<F>>, Ret, Args...>;
		}
		
		// Unsafe for storage.
		template<typename F> requires ( Invocable<F, Ret, Args...> && ( !Same<std::decay_t<F>, function_view> ) )
		function_view( F&& functor ) : function_view( functor ) {}

		// Default copy/move.
		//
		function_view( function_view&& ) = default;
		function_view( const function_view& ) = default;
		function_view& operator=( function_view&& ) = default;
		function_view& operator=( const function_view& ) = default;

		// Validity check via cast to bool.
		//
		explicit operator bool() const { return obj; }

		// Redirect to functor.
		//
		Ret operator()( Args... args )
		{
			return fn( obj, std::forward<Args>( args )... );
		}
		Ret operator()( Args... args ) const
		{
			fassert( const_invocable );
			return fn( obj, std::forward<Args>( args )... );
		}
	};
};