#pragma once
#include <type_traits>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <algorithm>
#include <functional>

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
			remapped_iterator() = default;
			remapped_iterator( const T & v ) : T( v ) {}
			remapped_iterator( T && v ) : T( std::move( v ) ) {}

			using base_type = T;
			auto& operator->() const { return &T::operator->()->value; }
			auto& operator->() { return &T::operator->()->value; }
			auto& operator*() const { return T::operator->()->value; }
			auto& operator*() { return T::operator->()->value; }
			
			template<bool c = is_const, std::enable_if_t<!c, int> =0> auto& inc_priority( int64_t n ) { T::operator->()->points += n; return *this; }
			template<bool c = is_const, std::enable_if_t<!c, int> =0> auto& dec_priority( int64_t n ) { T::operator->()->points -= n; return *this; }
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

		// const-qualifiers are ignored for mutex.
		//
		template<typename T = std::conditional_t<atomic, std::shared_mutex&, std::shared_mutex>>
		T get_mutex() const { return (T)mutex; }

		// Priority based iteration is done using these wrappers.
		//
		void for_each( const std::function<void( iterator )>& enumerator )
		{
			std::unique_lock _gd( get_mutex() );

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
			for ( auto& guide : snapshot )
				enumerator( guide.second );
		}
		void for_each( const std::function<void( const_iterator )>& enumerator ) const
		{
			std::shared_lock _gd( get_mutex() );

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
			for ( auto& guide : snapshot )
				enumerator( guide.second );
		}

		// Redirect size related std::list functions.
		//
		size_t size() const { std::shared_lock _g( get_mutex() ); return container.size(); }
		bool empty() const { std::shared_lock _g( get_mutex() ); return container.empty(); }

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
		iterator at( size_t n ) { std::shared_lock _g( get_mutex() ); return std::next( container.begin(), n ); }
		iterator operator[]( size_t n ) { return at( n ); }
		const_iterator at( size_t n ) const { std::shared_lock _g( get_mutex() ); return std::next( container.begin(), n ); }
		const_iterator operator[]( size_t n ) const { return at( n ); }
		void push_back( T&& v ) { std::unique_lock _g( get_mutex() ); container.push_back( std::move( v ) ); }
		void push_back( const T& v ) { std::unique_lock _g( get_mutex() ); container.push_back( v ); }
		void resize( size_t v ) { std::unique_lock _g( get_mutex() ); container.resize( v ); }
	};
};