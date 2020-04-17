#pragma once
#include <vector>
#include <iterator>
#include "range_iterator_contract.hpp"

// Range iterators are cross-container iterators used by the VTIL queries in order to make the 
// iteration of trees, in our specific use case the basic blocks, easier.
//
namespace vtil::query
{
	// Basic range iterators provide a simple range iterator implementation for default STL container and pretty much
	// any other container adhereing to their standarts to be used with VTIL queries.
	//
	template<typename container_type, 
		typename iterator_type = std::conditional_t<std::is_const_v<container_type>, typename container_type::const_iterator, typename container_type::iterator>>
	struct basic_range_iterator : iterator_type
	{
		using container_type = container_type;
		using iterator_type = iterator_type;

		// Reference to the container.
		//
		container_type* container = nullptr;

		// Default constructor and the container-bound constructor.
		//
		basic_range_iterator() = default;
		basic_range_iterator( container_type* container, iterator_type i ) : iterator_type( i ), container( container ) {}
		template<typename X, typename Y> basic_range_iterator( const basic_range_iterator<X, Y>& o ) : container( o.container ), iterator_type( Y( o ) ) {}

		// Override equality operators to check container first.
		//
		bool operator!=( const basic_range_iterator& o ) const { return container != o.container || iterator_type::operator!=( o ); }
		bool operator==( const basic_range_iterator& o ) const { return container == o.container && iterator_type::operator==( o ); }

		// Simple position/validity checks.
		//
		bool is_end() const { return !container || iterator_type::operator==( ( iterator_type ) container->end() ); }
		bool is_begin() const { return !container || iterator_type::operator==( ( iterator_type ) container->begin() ); }
		bool is_valid() const { return !is_begin() || !is_end(); }

		// No default implementation for recursion since STL has no default tree-based container.
		//
		std::vector<basic_range_iterator> recurse( bool forward ) const { return {}; }
	};

	// Makes range iterator from any container and iterator combination based on basic_range_iterator.
	//
	template<typename container_type, typename iterator_type>
	static auto bind( container_type& container, iterator_type iterator ) { return basic_range_iterator<container_type, iterator_type>{ &container, iterator }; }

	// Make sure contract is being abided.
	//
	static_assert
	(
		is_range_iterator_v<basic_range_iterator<std::vector<int>, std::vector<int>::iterator>>&&
		is_range_iterator_v<basic_range_iterator<const std::vector<int>, std::vector<int>::const_iterator>>&&
		"Basic range iterator does not abide by the range iterator contract."
	);
};