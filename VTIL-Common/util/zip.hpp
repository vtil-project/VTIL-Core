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
#include <tuple>
#include <iterator>
#include "type_helpers.hpp"
#include "optional_reference.hpp"

namespace vtil
{
	namespace impl
	{
		// References the N'th element of the container with no overflow checks.
		//
		template<typename T>
		struct doref_wrapper
		{
			constexpr decltype( auto ) operator()( T& o, size_t N ) const
			{
				return o[ N ];
			}
		};

		// References the N'th element of the container, repeats the elements from
		// the beginning if the limit is reached. If non-container type is passed
		// returns as is.
		//
		template<typename T>
		struct modref_wrapper
		{
			constexpr decltype( auto ) operator()( T& o, size_t N ) const
			{
				return o[ N % std::size( o ) ];
			}
		};

		// References the N'th element of the container, returns null reference
		// if the limit is reached. If non-container type is passed returns as is
		// for [0] and null reference after that.
		//
		template<typename T>
		struct optref_wrapper
		{
			constexpr auto operator()( T& o, size_t N ) const
			{
				if constexpr ( std::is_reference_v<o[ N ]> )
					return dereference_if_n( N < std::size( o ), std::begin( o ), N );
				else
					return N < std::size( o ) ? std::optional{ o[ N ] } : std::nullopt;
			}
		};
	};

	template<template<typename> typename accessor, typename... Tx>
	struct joint_container
	{
		// Declare the entry type.
		//
		using entry_type = std::tuple<decltype( accessor<Tx>{}( std::declval<Tx&>(), 0 ) )... >;

		// Declare the iterator type.
		//
		struct base_iterator
		{
			// Generic iterator typedefs.
			//
			using iterator_category = std::bidirectional_iterator_tag;
			using difference_type =   int;
			using value_type =        entry_type*;
			using pointer =           entry_type*;
			using reference =         entry_type&;

			// Self reference and the index.
			//
			const joint_container& container;
			size_t index;

			// Default constructor.
			//
			base_iterator( const joint_container& container, size_t index = 0 ) :
				container( container ), index( index ) {}

			// Support bidirectional iteration.
			//
			constexpr base_iterator& operator++() { ++index; return *this; }
			constexpr base_iterator& operator--() { --index; return *this; }
			constexpr base_iterator operator++( int ) { auto s = *this; operator++(); return s; }
			constexpr base_iterator operator--( int ) { auto s = *this; operator--(); return s; }

			// Equality check against another iterator.
			//
			constexpr bool operator==( const base_iterator& other ) const { return index == other.index && &container == &other.container; }
			constexpr bool operator!=( const base_iterator& other ) const { return index != other.index || &container != &other.container; }

			// Redirect dereferencing to container.
			//
			constexpr entry_type operator*() const { return container.at( index ); }
		};
		using iterator =       base_iterator;
		using const_iterator = base_iterator;

		// Tuple containing data sources.
		//
		std::tuple<Tx&...> sources;
		size_t size_0;

		constexpr joint_container( std::tuple<Tx&...>&& source )
			: sources( std::move( source ) ), size_0( std::size( std::get<0>( sources ) ) ) {}

		// Declare random access helper.
		//
		template<size_t... I>
		constexpr entry_type at( size_t idx, std::index_sequence<I...> ) const
		{
			return { accessor<Tx>{}( std::get<I>( sources ), idx )... };
		}
		constexpr entry_type at( size_t idx ) const
		{
			return at( idx, std::index_sequence_for<Tx...>{} );
		}

		// Generic container helpers.
		//
		constexpr size_t size() const { return size_0; }
		constexpr iterator begin() const { return { *this, 0 }; }
		constexpr iterator end() const { return { *this, size_0 }; }
	};

	// Simple joint container creation from wrappers.
	//
	template <typename... Tx> requires ( Iterable<Tx&> && ... )
	static constexpr auto zip_s( Tx&... args ) -> joint_container<impl::optref_wrapper, Tx...> { return { std::tie( args... ) }; }

	template <typename... Tx> requires ( Iterable<Tx&> && ... )
	static constexpr auto zip_c( Tx&... args ) -> joint_container<impl::modref_wrapper, Tx...> { return { std::tie( args... ) }; }

	template <typename... Tx> requires ( Iterable<Tx&> && ... )
	static constexpr auto zip( Tx&... args )   -> joint_container<impl::doref_wrapper, Tx...>  { return { std::tie( args... ) }; }
};