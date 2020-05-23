#pragma once
#include <tuple>
#include <iterator>
#include "dynamic_size.hpp"
#include "optional_reference.hpp"

namespace vtil
{
	namespace impl
	{
		// References the N'th element of the container, repeats the elements from
		// the beginning if the limit is reached. If non-container type is passed
		// returns as is.
		//
		template<typename T>
		struct modref_wrapper
		{
			auto& operator()( T& o, size_t N ) const
			{
				if constexpr ( is_random_access_v<T> )
					return o[ N % dynamic_size( o ) ];
				else
					return o;
			}
		};

		// References the N'th element of the container, returns null reference
		// if the limit is reached. If non-container type is passed returns as is
		// for [0] and null reference after that.
		//
		template<typename T>
		struct optref_wrapper
		{
			auto operator()( T& o, size_t N ) const
			{
				if constexpr ( is_random_access_v<T> )
					return dereference_if_n( N < dynamic_size( o ), std::begin( o ), N );
				else
					return dereference_if_n( N == 0, &o );
			}
		};
	};

	template<template<typename> typename accessor, typename... Tx>
	struct joint_container
	{
		// Declare the entry type.
		//
		using value_type = std::tuple<decltype( accessor<Tx>{}( std::declval<Tx&>(), 0 ) )... > ;

		// Declare the iterator type.
		//
		struct iterator_end_tag_t {};
		struct iterator : std::iterator<std::bidirectional_iterator_tag, value_type>
		{
			// Self reference.
			//
			const joint_container* container;
			
			// Range of iteration.
			//
			size_t index;
			size_t limit;

			// Default constructor.
			//
			iterator( const joint_container* container, size_t index = 0 ) :
				container( container ), index( index ), limit( container->size() ) {}

			// Support bidirectional iteration.
			//
			iterator& operator++() { index++; return *this; }
			iterator& operator--() { index--; return *this; }

			// Equality check against another iterator.
			//
			bool operator==( const iterator& other ) const 
			{ 
				return index == other.index && container == other.container; 
			}
			bool operator!=( const iterator& other ) const 
			{ 
				return index != other.index || container != other.container; 
			}
			
			// Equality check against special end iterator.
			//
			bool operator==( iterator_end_tag_t ) const { return index == limit; }
			bool operator!=( iterator_end_tag_t ) const { return index != limit; }

			// Redirect dereferencing to container.
			//
			value_type operator*() const { return container->at( index ); }
		};
		using const_iterator = iterator;

		// Tuple containing data sources.
		//
		std::tuple<Tx&...> sources;

		// Declare random access helper.
		//
		template<size_t... I>
		value_type at( size_t idx, std::index_sequence<I...> ) const
		{
			return { accessor<Tx>{}( std::get<I>( sources ), idx )... };
		}
		value_type at( size_t idx ) const
		{
			return at( idx, std::index_sequence_for<Tx...>{} );
		}

		// Generic container helpers.
		//
		size_t size() const { return dynamic_size( std::get<0>( sources ) ); }
		iterator begin() const { return { this, 0 }; }
		iterator_end_tag_t end() const { return {}; }
	};

	// Simple joint container creation from wrappers.
	//
	template <typename... Tx>
	static auto zip_s( Tx&... args ) -> joint_container<impl::optref_wrapper, Tx...>
	{ 
		return { std::tie( args... ) }; 
	}
	template <typename... Tx>
	static auto zip( Tx&... args ) -> joint_container<impl::modref_wrapper, Tx...>
	{
		return { std::tie( args... ) };
	}
};