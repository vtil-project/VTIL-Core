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
#include <functional>
#include "interface.hpp"

namespace vtil
{
	namespace impl
	{
		// Strips the object that this function belongs to.
		//
		template<typename T>
		struct strip_object { using type = std::function<T>; };
		template<typename R, typename O, typename... A>
		struct strip_object<R( O::* )( A... ) const> { using type = std::function<R( A... )>; };
		template<typename R, typename O, typename... A>
		struct strip_object<R( O::* )( A... )> { using type = std::function<R( A... )>; };
		template<typename T>
		using strip_object_t = typename strip_object<T>::type;
	};
	
	// Declare a virtual machine where all calls are redirected to lambda callbacks.
	//
	template<typename vm_base = vm_interface>
	struct lambda_vm : vm_base
	{
		// Declare std::function instances based on the stripped signature for each function we hijack.
		//
		struct
		{
			impl::strip_object_t<decltype( &vm_interface::size_register )> size_register = {};
			impl::strip_object_t<decltype( &vm_interface::read_register )> read_register = {};
			impl::strip_object_t<decltype( &vm_interface::read_memory )> read_memory = {};
			impl::strip_object_t<decltype( &vm_interface::write_register )> write_register = {};
			impl::strip_object_t<decltype( &vm_interface::write_memory )> write_memory = {};
			impl::strip_object_t<decltype( &vm_interface::execute )> execute = {};
		} hooks;

		// Declare the overrides redirecting to the callbacks.
		//
		bitcnt_t size_register( const register_desc& desc ) override 
		{
			return hooks.size_register
				? hooks.size_register( desc )
				: vm_base::size_register( desc );
		}
		symbolic::expression::reference read_register( const register_desc& desc ) override
		{
			return hooks.read_register 
				? hooks.read_register( desc ) 
				: vm_base::read_register( desc );
		}
		symbolic::expression::reference read_memory( const symbolic::expression::reference& pointer, size_t byte_count ) override
		{ 
			return hooks.read_memory 
				? hooks.read_memory( pointer, byte_count ) 
				: vm_base::read_memory( pointer, byte_count );
		}
		void write_register( const register_desc& desc, symbolic::expression::reference value ) override
		{ 
			return hooks.write_register 
				? hooks.write_register( desc, std::move( value ) ) 
				: vm_base::write_register( desc, std::move( value ) );
		}
		void write_memory( const symbolic::expression::reference& pointer, symbolic::expression::reference value ) override
		{
			return hooks.write_memory
				? hooks.write_memory( pointer, std::move( value ) )
				: vm_base::write_memory( pointer, std::move( value ) );
		}
		bool execute( const instruction& ins ) override
		{
			return hooks.execute
				? hooks.execute( ins )
				: vm_base::execute( ins );
		}
	};
};