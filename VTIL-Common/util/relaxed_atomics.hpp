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
#include <atomic>
#include "type_helpers.hpp"

namespace vtil
{
	// Implements a wrapper around std::atomic/?mutex that makes it copyable. This is deleted for valid
	// reasons in the base class, however when used as a class member, it forces the object to
	// implement a custom constructor which in most cases not needed since object can be reasonably
	// assumed to be not copied in the first place while it is still being operated.
	//
	template<typename T>
	struct relaxed_atomic : std::atomic<T>
	{
		// Inerit assignment and construction.
		//
		using base_type = std::atomic<T>;
		using base_type::base_type;
		using base_type::operator=;

		// Allow copy construction and assignment.
		//
		relaxed_atomic( const relaxed_atomic& o ) : base_type( o.load() ) {}
		relaxed_atomic& operator=( const relaxed_atomic& o ) { base_type::operator=( o.load() ); return *this; }
	};
	template<typename T>
	struct relaxed_mutex : T
	{
		// Inerit construction.
		//
		using base_type = T;
		using base_type::base_type;

		// Allow copy/move construction and assignment, safety is left to the owner.
		//
		relaxed_mutex( relaxed_mutex&& o ) {}
		relaxed_mutex( const relaxed_mutex& o ) {}
		relaxed_mutex& operator=( relaxed_mutex&& o ) { return *this; }
		relaxed_mutex& operator=( const relaxed_mutex& o ) { return *this; }
	};
	namespace impl
	{
		template<typename T>
		struct relaxed_type;
		template<Atomic T>   struct relaxed_type<T> { using type = relaxed_atomic<typename T::value_type>; };
		template<Lockable T> struct relaxed_type<T> { using type = relaxed_mutex<T>; };
	};
	template<typename T>
	using relaxed = typename impl::relaxed_type<T>::type;
};