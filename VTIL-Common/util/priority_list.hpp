// Copyright (c) 2020 Can Bölük and contributors of the VTIL Project		   
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
// Furthermode, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information				      |
// |-------------------------|------------------------------------------------|
// | amd64/*                 | https://github.com/aquynh/capstone/		      |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#pragma once
#include <type_traits>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <algorithm>
#include <functional>
#include <optional>

namespace vtil
{
	// Provides a (optionally atomic) list where entries are sorted by "points".
	//
	template<typename T, bool atomic = false>
	struct priority_list
	{
		// Entry type wrapping the actual object.
		//
		struct entry_type
		{
			T value = {};
			std::atomic<int64_t> points = 0;

			entry_type() = default;
			entry_type( entry_type&& entry ) : points( entry.points.load() ), value( std::move( entry.value ) ) {}
			entry_type( const entry_type& entry ) : points( entry.points.load() ), value( entry.value ) {}
			entry_type( const T & value ) : value( value ) {}
			entry_type( T&& value ) : value( std::move( value ) ) {}
		};

		// Remapped iterator hiding the base entry_type from the user.
		//
		template<typename T, bool is_const = false>
		struct remapped_iterator : T
		{
			using base_type = T;

			remapped_iterator() = default;
			remapped_iterator( const T & v ) : T( v ) {}
			remapped_iterator( T&& v ) : T( std::move( v ) ) {}

			auto* operator->() const { return &T::operator->()->value; }
			auto& operator*() const { return T::operator->()->value; }
			
			template<bool c = is_const, std::enable_if_t<!c, int> =0> auto& inc_priority( int64_t n ) { T::operator->()->points += n; return *this; }
			template<bool c = is_const, std::enable_if_t<!c, int> =0> auto& dec_priority( int64_t n ) { T::operator->()->points -= n; return *this; }

			auto operator==( remapped_iterator& o ) const { return T::operator==( o ); }
			auto operator!=( remapped_iterator& o ) const { return T::operator!=( o ); }
		};

		// Use std::list for atomic priority lists, and std::vector otherwise.
		//
		using container_type = typename std::conditional_t<atomic, std::list<entry_type>, std::vector<entry_type>>;

		// Define standard container properties.
		//
		using value_type = entry_type;
        using pointer = value_type*;
        using const_pointer = const value_type*;
        using reference = value_type&;
        using const_reference = const value_type&;
		using iterator = remapped_iterator<typename container_type::iterator>;
		using const_iterator = remapped_iterator<typename container_type::const_iterator, true>;
		using reverse_iterator = remapped_iterator<typename container_type::reverse_iterator>;
		using const_reverse_iterator = remapped_iterator<typename container_type::const_reverse_iterator, true>;

		// Mutex for atomic lists, which may be unused, and the container itself.
		//
		std::shared_mutex mutex;
		container_type container;

		// Mutex ignores const-qualifiers.
		//
		std::shared_mutex* get_mutex() const
		{
			return ( std::shared_mutex* ) &mutex;
		}

		// Default constructors and copy/move.
		//
		priority_list() = default;
		priority_list( const priority_list& ) = delete;
		priority_list& operator=( const priority_list& ) = delete;
		priority_list( priority_list&& ) = default;
		priority_list& operator=( priority_list&& ) = default;

		// Construct from a list of initial values.
		//
		priority_list( const std::initializer_list<T>& init_list )
		{
			for ( T& entry : init_list )
				push_back( entry );
		}
		priority_list( std::initializer_list<T>&& init_list )
		{
			for ( T& entry : init_list )
				push_back( std::move( entry ) );
		}

		// Priority based iteration is done using these wrappers.
		//
		template<typename T>
		std::optional<T> for_each( const std::function<std::optional<T>( iterator )>& enumerator )
		{
			if ( auto m = get_mutex() ) m->lock_shared();

			// Take a snapshot of current points.
			//
			std::vector<std::pair<int64_t, iterator>> snapshot;
			snapshot.reserve( container.size() );
			for ( auto it = begin(); it != end(); it++ )
				snapshot.push_back( { iterator::base_type( it )->points, it } );

			// Sort the snapshot, descending in terms of points.
			//
			std::sort( snapshot.begin(), snapshot.end(), [ ] ( auto& a, auto& b ) { return a.first > b.first; } );

			// Iterate according to the guide and invoke enumerator.
			//
			std::optional<T> result;
			for ( auto& guide : snapshot )
			{
				if ( auto r = enumerator( guide.second ) )
				{
					result = r;
					break;
				}
			}

			if ( auto m = get_mutex() ) m->unlock_shared();
			return result;
		}

		template<typename T>
		std::optional<T> for_each( const std::function<std::optional<T>( const_iterator )>& enumerator ) const
		{
			if ( auto m = get_mutex() ) m->lock_shared();

			// Take a snapshot of current points.
			//
			std::vector<std::pair<int64_t, const_iterator>> snapshot;
			snapshot.reserve( container.size() );
			for ( auto it = begin(); it != end(); it++ )
				snapshot.push_back( { const_iterator::base_type( it )->points, it } );

			// Sort the snapshot, descending in terms of points.
			//
			std::sort( snapshot.begin(), snapshot.end(), [ ] ( auto& a, auto& b ) { return a.first > b.first; } );

			// Iterate according to the guide and invoke enumerator.
			//
			std::optional<T> result;
			for ( auto& guide : snapshot )
			{
				if ( auto r = enumerator( guide.second ) )
				{
					result = r;
					break;
				}
			}

			if ( auto m = get_mutex() ) m->unlock_shared();
			return result;
		}

		// Redirect size related std::list functions.
		//
		size_t size() const { if ( auto m = get_mutex() ) m->lock_shared(); auto r = container.size(); if ( auto m = get_mutex() ) m->unlock_shared(); return r; }
		bool empty() const { if ( auto m = get_mutex() ) m->lock_shared(); auto r = container.empty(); if ( auto m = get_mutex() ) m->unlock_shared(); return r; }

		// Redirect iteration related std::list functions.
		// - Note: Unsafe, if lock not aquired.
		//
		iterator begin() { return container.begin(); }
		iterator end() { return container.end(); }
		reverse_iterator rbegin() { return container.rbegin(); }
		reverse_iterator rend() { return container.rend(); }
		const_iterator begin() const { return container.begin(); }
		const_iterator end() const { return container.end(); }
		const_reverse_iterator rbegin() const { return container.rbegin(); }
		const_reverse_iterator rend() const { return container.rend(); }

		// Redirect data related std::list functions.
		//
		iterator at( size_t n ) { if ( auto m = get_mutex() ) m->lock_shared(); auto r = std::next( container.begin(), n ); if ( auto m = get_mutex() ) m->unlock_shared(); return r; }
		iterator operator[]( size_t n ) { return at( n ); }
		const_iterator at( size_t n ) const { if ( auto m = get_mutex() ) m->lock_shared(); auto r = std::next( container.begin(), n ); if ( auto m = get_mutex() ) m->unlock_shared(); return r; }
		const_iterator operator[]( size_t n ) const { return at( n ); }
		void push_back( T&& v ) { if ( auto m = get_mutex() ) m->lock(); container.push_back( std::move( v ) ); if ( auto m = get_mutex() ) m->unlock(); }
		void push_back( const T& v ) { if ( auto m = get_mutex() ) m->lock(); container.push_back( v ); if ( auto m = get_mutex() ) m->unlock(); }
		void resize( size_t v ) { if ( auto m = get_mutex() ) m->lock(); container.resize( v ); if ( auto m = get_mutex() ) m->unlock(); }
	};
};