#pragma once
#include <ostream>
#include <istream>
#include <vector>
#include <string>
#include "routine.hpp"
#include "basic_block.hpp"
#include "instruction.hpp"

namespace vtil
{
	namespace impl
	{
		// Check if type is a standard container.
		//
		template <typename T>
		static constexpr bool _is_std_container( ... ) { return false; }
		template <typename container_type,
			typename iterator_type = typename container_type::iterator,
			typename = decltype( std::declval<container_type>().begin() ),
			typename = decltype( std::declval<container_type>().end() ),
			typename = decltype( std::declval<container_type>().clear() ),
			typename = decltype( std::declval<container_type>().insert( std::declval<container_type>().begin(), *std::declval<container_type>().begin() ) ) >
		static constexpr bool _is_std_container( bool v ) { return true; }

		template <typename T>
		static constexpr bool is_std_container_v = _is_std_container<std::remove_cvref_t<T>>( true );

		// Check if the type is a linear container. (std::vector or std::*string)
		//
		template <typename T> struct _is_linear_container : std::false_type {};
		template <typename T> struct _is_linear_container<std::vector<T>> : std::true_type {};
		template <typename T> struct _is_linear_container<std::basic_string<T>> : std::true_type {};
		
		template <typename T>
		static constexpr bool is_linear_container_v = _is_linear_container<std::remove_cvref_t<T>>::value;

		// Check if the container::push_back(value&&) is valid.
		//
		template <typename T>
		static constexpr bool _has_push_back( ... ) { return false; }
		template <typename container_type, typename = decltype( std::declval<container_type>().push_back( std::declval<typename container_type::value_type&&>() ) )>
		static constexpr auto _has_push_back( bool v ) { return true; }
		
		template <typename T>
		static constexpr bool has_push_back_v = _has_push_back<std::remove_cvref_t<T>>( true );
		
		// Check if the container::insert(value&&) is valid.
		//
		template <typename T>
		static constexpr bool _has_insert_value( ... ) { return false; }
		template <typename container_type, typename = decltype( std::declval<container_type>().insert( std::declval<typename container_type::value_type&&>() ) )>
		static constexpr auto _has_insert_value( bool v ) { return true; }
		
		template <typename T>
		static constexpr bool has_insert_value_v = _has_insert_value<std::remove_cvref_t<T>>( true );

		// Move the given value to the end of the container.
		//
		template<typename T>
		static void move_back( T& container, typename T::value_type&& value )
		{
			if constexpr ( has_push_back_v<T> )
				container.push_back( std::move( value ) );
			else if constexpr ( has_insert_value_v<T> )
				container.insert( std::move( value ) );
			else
				container.insert( container.end(), std::move( value ) );
		}
	};

	// Container lengths are encoded using 32-bit integers instead of the 64-bit size_t.
	//
	using clength_t = uint32_t;

	// Serialization of VTIL instructions.
	//
	void serialize( std::ostream& out, const instruction& in );
	void deserialize( std::istream& in, instruction& out );

	// Serialization of VTIL blocks.
	//
	void serialize( std::ostream& out, const basic_block* in );
	void deserialize( std::istream& in, routine* rtn, basic_block*& blk );

	// Serialization of VTIL routines.
	//
	void serialize( std::ostream& out, const routine* rtn );
	routine* deserialize( std::istream& in, routine*& rtn );

	// Serialization of any type except standard containers and pointers.
	//
	template<typename T, std::enable_if_t<!std::is_pointer_v<T> && !impl::is_std_container_v<T>, int> = 0>
	static void serialize( std::ostream& ss, const T& v ) 
	{ 
		ss.write( ( const char* ) &v, sizeof( T ) ); 
	}
	template<typename T, std::enable_if_t<!std::is_pointer_v<T> && !impl::is_std_container_v<T>, int> = 0>
	static void deserialize( std::istream& ss, T& v ) 
	{ 
		ss.read( ( char* ) &v, sizeof( T ) ); 
	}

	// Serialization of standard containers.
	//
	template<typename T, std::enable_if_t<impl::is_std_container_v<T>, int> = 0>
	static void serialize( std::ostream& ss, const T& v )
	{
		// Serialize the number of entries.
		//
		serialize<clength_t>( ss, v.size() );

		// Serialize each entry.
		//
		for( auto& entry : v ) 
			serialize( ss, entry );
	}
	template<typename T, std::enable_if_t<impl::is_std_container_v<T>, int> = 0>
	static void deserialize( std::istream& ss, T& v )
	{
		using value_type = typename T::value_type;

		// Deserialize the entry counter from the stream and reset the container.
		//
		clength_t n;
		deserialize( ss, n );

		// If container stores data linearly and trivial data is stored:
		//
		if constexpr ( impl::is_linear_container_v<T> && std::is_trivial<T>::value )
		{
			// Resize the container to expected size and read all entries at once.
			//
			v.resize( n );
			ss.read( ( char* ) v.data(), n * sizeof( value_type ) );
			return;
		}
		
		// Clear the container just in-case.
		//
		v.clear();

		// Until counter reaches zero, deserialize an entry and then insert it at the end.
		//
		while ( n-- )
		{
			value_type value;
			deserialize( ss, value );
			impl::move_back( v, std::move( value ) );
		}
	}
};