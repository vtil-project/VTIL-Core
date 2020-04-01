#pragma once
#include <vector>

namespace vtil::query
{
	// Basic range iterators provide a simple range iterator
	// implementation for default STL objects and pretty much
	// any other class adhereing to their standarts, to be used
	// with VTIL queries.
	//
	template<typename _container_type, typename _iterator_type>
	struct range_iterator : _iterator_type
	{
		using container_type = _container_type;
		using iterator_type = _iterator_type;

		// Reference to the container.
		//
		container_type* container = nullptr;

		// Default constructor and the container-bound constructor.
		//
		range_iterator() {}
		range_iterator( _container_type* container, _iterator_type i ) : iterator_type( i ), container( container ) {}
		template<typename X, typename Y> range_iterator( const range_iterator<X, Y>& o ) : container( o.container ), iterator_type( o ) {}

		// Simple position/validity checks.
		//
		bool is_begin() const { return !container || container->begin() == *this; }
		bool is_end() const { return !container || container->end() == *this; }
		bool is_valid() const { return !is_begin() || !is_end(); }

		// No default implementation for recursion since STL has no default tree-based container.
		//
		std::vector<range_iterator> recurse( bool forward ) const { return {}; }
	};

	// Makes range iterator from any container and iterator combination based on basic_range_iterator.
	//
	template<typename container_type>
	static auto bind( container_type& container, typename container_type::iterator iterator )
	{
		return range_iterator<container_type, typename container_type::iterator>
		{
			&container,
			iterator
		};
	}
	template<typename container_type>
	static auto bind( const container_type& container, typename container_type::const_iterator iterator )
	{
		return range_iterator<const container_type, typename container_type::const_iterator>
		{
			&container,
			iterator
		};
	}
};