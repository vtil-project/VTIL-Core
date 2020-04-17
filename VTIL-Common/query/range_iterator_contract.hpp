#pragma once
#include <iterator>
#include <type_traits>

// We implement a simple type-traits like template to check if an arbitrary type 
// abides by the range iterator contract.
//
namespace vtil::query
{
	namespace impl
	{
		template<typename _T>
		static constexpr bool _is_range_iterator( bool )
		{
			using T = typename std::remove_cvref_t<_T>;

			// Must be inheriting from the iterator type, exported as T::iterator_type.
			// - struct T : T::iterator_type {};
			//
			if ( !std::is_base_of_v<typename T::iterator_type, T> )
				return false;

			// Must have a public member called .container that is of type T::container_type*.
			// - T::container_type* T::container;
			//
			using container_type_a = std::remove_pointer_t<decltype( std::declval<T>().container )>;
			using container_type_b = typename T::container_type;
			if ( !std::is_same_v<container_type_a, container_type_b> )
				return false;

			// Must have the basic comparison checks implemented.
			// - bool T::operator==(const T& o);
			// - bool T::operator!=(const T& o);
			//
			using comparison_assertation_1 = decltype( bool( std::declval<const T>() == std::declval<const T>() ) );
			using comparison_assertation_2 = decltype( bool( std::declval<const T>() != std::declval<const T>() ) );

			// Must be compatible with std::prev and std::next, meaning
			// a fully functional bidirectional iterator.
			// - X T::operator++();
			// - X T::operator--();
			// - X ++T::operator();
			// - X --T::operator();
			//
			using prev_type = decltype( std::prev( std::declval<T::iterator_type>(), 0x1337 ) );
			using prev_type = decltype( std::next( std::declval<T::iterator_type>(), 0x1337 ) );


			// Must have the container-abstracting range checks implemented.
			// - bool T::is_begin();
			// - bool T::is_end();
			// - bool T::is_valid();
			//
			using range_check_1 = decltype( bool( std::declval<const T>().is_begin() ) );
			using range_check_2 = decltype( bool( std::declval<const T>().is_end() ) );
			using range_check_3 = decltype( bool( std::declval<const T>().is_valid() ) );

			// Must have recursion helpers implemented, even if no-op.
			//
			// - container_type T::recurse(bool)
			//   - container_iterator_type container_type::begin()
			//   - container_iterator_type container_type::end()
			//
			using recurse_retval = decltype( std::declval<const T>().recurse( false ) );
			using container_iterator_begin = decltype( std::declval<recurse_retval>().begin() );
			using container_iterator_end = decltype( std::declval<recurse_retval>().end() );
			using container_iterator_value = std::remove_cvref_t<decltype( *std::declval<container_iterator_begin>() )>;
			using container_iterator_pointer = std::remove_cvref_t<decltype( std::declval<container_iterator_begin>().operator->() )>;

			return std::is_same_v<std::remove_cvref_t<container_iterator_value>, T> && 
				   std::is_same_v<std::remove_cvref_t<container_iterator_pointer>, T*>;
		}

		template<typename T>
		static constexpr bool _is_range_iterator( ... ) { return false; }
	};
	template<typename T>
	static constexpr bool is_range_iterator_v = impl::_is_range_iterator<T>( true );
};