#pragma once
#include <algorithm>
#include "concept.hpp"

namespace vtil
{
	namespace impl
	{
		// Determines whether the object is random-accessable by definition or not.
		//
		template<typename... D>
		struct is_default_ra : concept_base<is_default_ra, D...>
		{
			template<typename T>
			static auto f( const T& v ) -> decltype( v[ 0 ], std::size( v ) );
		};

		// Determine whether the object is random-accessable by a custom interface or not.
		//
		template<typename... D>
		struct is_cutom_ra : concept_base<is_cutom_ra, D...>
		{
			template<typename T>
			static auto f( const T& v ) -> decltype( v[ 0 ], v.size() );
		};
	};

	// Returns whether the given object is a random-accessable container or not.
	//
	template<typename T>
	static constexpr bool is_random_access_v = 
		impl::is_default_ra<T>::apply() ||
		impl::is_cutom_ra<T>::apply();

	// Gets the size of the given container.
	//
	template<typename T>
	static size_t dynamic_size( T& o )
	{
		if constexpr ( impl::is_default_ra<T>::apply() )
			return std::size( o );
		else if constexpr ( impl::is_cutom_ra<T>::apply() )
			return o.size();
		return 0;
	}

	// Gets the Nth element from the object.
	//
	template<typename T>
	static auto& deref_n( T& o, size_t N )
	{
		return o[ N ];
	}
};