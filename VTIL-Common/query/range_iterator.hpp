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
#include <vector>
#include <iterator>
#include "range_iterator_contract.hpp"

// Range iterators are cross-container iterators used by the VTIL queries in order to make the 
// iteration of trees, in our specific use case the basic blocks, easier.
//
namespace vtil::query
{
	// Basic range iterators provide a simple range iterator implementation for default STL container and pretty much
	// any other container adhereing to their standards to be used with VTIL queries.
	//
	template<typename _container_type,
		typename _iterator_type = std::conditional_t<std::is_const_v<_container_type>, typename _container_type::const_iterator, typename _container_type::iterator>>
	struct basic_range_iterator : _iterator_type
	{
		using container_type = _container_type;
		using iterator_type = _iterator_type;

		// Reference to the container.
		//
		container_type* container = nullptr;

		// Default constructor and the container-bound constructor.
		//
		basic_range_iterator() {}
		basic_range_iterator( container_type* container, iterator_type i ) : iterator_type( i ), container( container ) {}
		template<typename X, typename Y> basic_range_iterator( const basic_range_iterator<X, Y>& o ) : container( o.container ), iterator_type( Y( o ) ) {}

		// Override equality operators to check container first.
		//
		bool operator!=( const basic_range_iterator& o ) const { return container != o.container || ( ( const iterator_type& ) *this ) != o; }
		bool operator==( const basic_range_iterator& o ) const { return container == o.container && ( ( const iterator_type& ) *this ) == o; }

		// Simple position/validity checks.
		//
		bool is_end() const { return !container || operator==( { container, container->end() } ); }
		bool is_begin() const { return !container || operator==( { container, container->begin() } ); }
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