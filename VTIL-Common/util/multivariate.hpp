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
		multivariate( multivariate&& o )
		{
			database = std::move( o.database );
		}
		multivariate& operator=( const multivariate& o )
		{
			std::lock_guard _g{ o.mtx }, _g2{ mtx };
			database = o.database;
		}
		multivariate& operator=( multivariate&& o )
		{
			std::lock_guard _g{ mtx };
			database = std::move( o.database );
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