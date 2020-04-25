#pragma once
#include <type_traits>
#include <functional>
#include <string>

// Poor man's concept, until C++20 hits widespread.
//
namespace vtil
{
	// Abuse SFINAE to detect feasability.
	//
	template<typename concept_type, typename... T>
	static constexpr auto test_concept( ... ) -> int;
	template<typename concept_type, typename... T>
	static constexpr auto test_concept( bool x )->std::void_t<decltype( concept_type::f( std::declval<T>()... ) )>;
	template<typename concept_type, typename... T>
	static constexpr bool test_concept_v = std::is_same_v<decltype( test_concept<concept_type, T...>( false ) ), void>;

	// Define a base type to generalize the checks.
	//
	template<template<typename...> typename C, typename... T>
	struct concept_base
	{
		static constexpr bool apply() { return test_concept_v<C<T...>, T...>; }
	};
};