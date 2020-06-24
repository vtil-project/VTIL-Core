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
#pragma once
#include <map>
#include <mutex>
#include "variant.hpp"
#include "lt_typeid.hpp"

namespace vtil
{
	// Multivariates store multiple types in a non-template type, mainly to be used by
	// optimizers to store arbitrary per-block / per-instruction data at the respective 
	// structures directly.
	//
	struct multivariate
	{
		mutable std::mutex mtx;
		mutable std::map<size_t, variant> database;

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
		const void purge() const
		{
			std::lock_guard _g{ mtx };
			database.erase( lt_typeid<T>::value );
		}

		// Checks if we have the type in the store.
		//
		template<typename T>
		const bool has() const
		{
			std::lock_guard _g{ mtx };
			return database.contains( lt_typeid<T>::value );
		}

		// Functional getter, if variant is already in the database will return
		// a reference to the stored data as is, otherwise will construct an empty 
		// T{} and place it in the database before referencing, eventhough the const use
		// is mutable, structure wraps each access to the database with a mutex so the
		// indexing is still thread-safe.
		//
		template<typename T>
		const T& get() const
		{
			// If variant is already in the database, return as is, else
			// default construct it and reference that instead.
			//
			std::lock_guard _g{ mtx };
			variant& var = database[ lt_typeid<T>::value ];
			if( !var ) var = T{};
			return var.get<T>();
		}
		template<typename T>
		T& get() { return const_cast< T& >( ( ( const multivariate* ) this )->get<T>() ); }

		// Allows for convinient use of the type in the format of:
		// - block_cache& cache = multivariate;
		//
		template<typename T>
		operator T&() { return get<T>(); }
		template<typename T>
		operator const T&() const { return get<T>(); }
	};
};