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
#include <map>
#include <mutex>
#include "variant.hpp"
#include "lt_typeid.hpp"
#include "type_helpers.hpp"

namespace vtil
{
	// If context type inherits from this type, the result of [T& T::update( owner* )] will be returned instead of T&.
	//
	struct mv_updatable_tag {};

	// Multivariates store multiple types in a non-template type, mainly to be used by
	// optimizers to store arbitrary per-block / per-instruction data at the respective 
	// structures directly.
	//
	// - Should pass self as template type and be named "::context" if we are expected to pass 
	//   owner in the constructor to the type.
	//
	template<typename owner = void>
	struct multivariate
	{
		mutable std::mutex mtx;
		mutable std::unordered_map<size_t, variant> database;

		// Default constructor.
		//
		multivariate() = default;

		// Allow copy/move construction/assignment.
		//
		multivariate( const multivariate& o )
		{
			std::lock_guard _g{ o.mtx };
			database = o.database;
		}
		multivariate( multivariate&& o ) noexcept
		{
			database = std::move( o.database );
		}
		multivariate& operator=( const multivariate& o )
		{
			std::lock_guard _g{ o.mtx }, _g2{ mtx };
			database = o.database;
			return *this;
		}
		multivariate& operator=( multivariate&& o ) noexcept
		{
			std::lock_guard _g{ mtx };
			database = std::move( o.database );
			return *this;
		}

		// Purges the object of the given type from the store.
		//
		template<typename T>
		void purge() const
		{
			std::lock_guard _g{ mtx };
			database.erase( lt_typeid_v<T> );
		}

		// Checks if we have the type in the store.
		//
		template<typename T>
		bool has() const
		{
			std::lock_guard _g{ mtx };
			return database.contains( lt_typeid_v<T> );
		}

		// Getter of the types.
		//
		template<typename T>
		auto& get() const
		{
			// Acquire the database lock and check for existance.
			//
			std::lock_guard _g{ mtx };
			variant& var = database[ lt_typeid_v<T> ];

			// If not constructed yet:
			//
			if ( !var ) var = T();

			// Return the appropriate reference.
			//
			T& ref = var.get<T>();
			if constexpr ( std::is_base_of_v<mv_updatable_tag, T> )
				return ref.update( ( owner* ) ptr_at<>( this, -make_offset( &owner::context ) ) );
			else
				return ref;
		}
		template<typename T>
		auto& get() { return make_const( this )->template get<T>(); }

		// Allows for convinient use of the type in the format of:
		// - block_cache& cache = multivariate;
		//
		template<typename T>
		operator T&() { return get<T>(); }
		template<typename T>
		operator const T&() const { return get<T>(); }
	};
};
