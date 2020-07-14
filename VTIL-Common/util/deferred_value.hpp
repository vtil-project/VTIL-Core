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
#include <tuple>
#include <optional>
#include <variant>
#include "type_helpers.hpp"

namespace vtil
{
	// Lightweight version of std::async::deferred that does not store any 
	// type-erased functions nor does any heap allocation.
	//
	template<typename Ret, typename Fn, typename... Tx>
	struct deferred_value
	{
		// Has the functor and its arguments.
		//
		struct pending_value
		{
			Fn functor;
			std::tuple<Tx...> arguments;
		};
		// Has the final value.
		//
		using known_value = Ret;
		// Declares invalid.
		//
		struct null_value {};

		// Current value.
		//
		std::variant<pending_value, known_value, null_value> value;

		// Null constructor.
		//
		deferred_value() : value( null_value{} ) {}
		deferred_value( std::nullopt_t ) : value( null_value{} ) {}

		// Construct by functor and its arguments.
		//
		deferred_value( Fn&& functor, Tx&&... arguments )
			: value( pending_value{ .functor = std::forward<Fn>( functor ), .arguments = { std::forward<Tx>( arguments )... } } ) {}

		// Constructor by known result.
		//
		deferred_value( Ret&& v ) : value( v ) {}
		deferred_value( const Ret& v ) : value( v ) {}
		
		// No move/copy.
		//
		deferred_value( deferred_value&& ) = delete;
		deferred_value( const deferred_value& ) = delete;

		// Returns a reference to the final value stored.
		//
		Ret& get()
		{
			// Convert pending value to known value.
			//
			if ( auto pending = std::get_if<pending_value>( &value ) )
				return value.emplace<1>( std::apply( std::move( pending->functor ), std::move( pending->arguments ) ) );

			// Return a reference to known value.
			//
			return std::get<1>( value );
		}
		const Ret& get() const { return make_mutable( this )->get(); }

		// Simple wrappers to check state.
		//
		bool is_valid() const { return value.index() != 2; }
		bool is_pending() const { return value.index() == 0; }
		bool is_known() const { return value.index() == 1; }

		// Assigns a value, discarding the pending invocation if relevant.
		//
		template<typename T>
		Ret& operator=( T&& new_value ) { return value.emplace<1>( std::forward<T>( new_value ) ); }

		// Syntax sugars.
		//
		Ret& operator*() { return get(); }
		Ret* operator->() { return &get(); }
		const Ret& operator*() const { return get(); }
		const Ret* operator->() const { return &get(); }

		// Implicit cast to value reference.
		//
		operator Ret&() { return get(); }
		operator const Ret&() const { return get(); }
	};

	// Declare deduction guide.
	//
	template<typename Fn, typename... Tx>
	deferred_value( Fn&&, Tx&&... ) -> deferred_value<decltype(std::declval<Fn&&>()(std::declval<Tx&&>()...)), Fn, Tx...>;
};