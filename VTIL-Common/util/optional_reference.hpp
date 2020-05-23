#pragma once
#include <type_traits>
#include <optional>
#include "hashable.hpp"
#include "reducable.hpp"

namespace vtil
{
	// Replicates the expected behaviour of std::optional<T&>.
	//
	template<typename T>
	struct optional_reference
	{
		T* pointer = nullptr;
		
		// Default constructor / move / copy.
		//
		optional_reference() = default;
		optional_reference( optional_reference&& ) = default;
		optional_reference( const optional_reference& ) = default;
		optional_reference& operator=( optional_reference&& ) = default;
		optional_reference& operator=( const optional_reference& ) = default;

		// Null reference constructors.
		//
		optional_reference( std::nullopt_t ) : pointer( nullptr ) {}
		
		// Constructs by reference to type.
		//
		optional_reference( T& ref )
			: pointer( &ref ) {}
		optional_reference( std::optional<T>& ref )
			: pointer( ref.has_value() ? &ref.value() : nullptr ) {}

		// Optional assignment to reference stored.
		//
		void assign_if( T&& value ) const { if ( pointer ) *pointer = value; }
		void assign_if( const T& value ) const { if ( pointer ) *pointer = value; }

		// Implement observers, mimicking std::optional<T>.
		// -------------------------------------------------
		// Accesses the contained value.
		//
		T& value() { return *pointer; }
		T& value() const { return *pointer; }
		T value_or( const T& def ) const { return has_value() ? value() : def; }
		T& value_or( std::remove_const_t<T>& def ) const { return has_value() ? value() : def; }
		T& operator*() { return value(); }
		T& operator*() const { return value(); }
		T* operator->() { return pointer; }
		T* operator->() const { return pointer; }

		// Checks whether the object contains a value.
		//
		bool has_value() const { return pointer != nullptr; }
		explicit operator bool() const { return has_value(); }

		// Implement modifiers, mimicking std::optional<T>.
		// -------------------------------------------------
		// Destroys currently held reference.
		//
		void reset() { pointer = nullptr; }

		// Constructs the contained value in-place.
		//
		void emplace( T& ref ) { pointer = &ref; }

		// Decays the reference to a constant qualified instance.
		//
		operator optional_reference<const T>() const { return { pointer }; }

		// Implement comparison operators mimicking the rules of std::optional<T>. 
		// - See: https://en.cppreference.com/w/cpp/utility/optional/operator_cmp.
		//
		template<typename R = decltype( std::declval<const T&>() > std::declval<const T&>() )>
		R operator>( const optional_reference& other ) const
		{
			return has_value() ? !other.has_value() || value() > other.value()  : false;
		}
		template<typename R = decltype( std::declval<const T&>() >= std::declval<const T&>() )>
		R operator>=( const optional_reference& other ) const
		{
			return has_value() ? !other.has_value() || value() >= other.value() : !other.has_value();
		}
		template<typename R = decltype( std::declval<const T&>() == std::declval<const T&>() )>
		R operator==( const optional_reference& other ) const
		{
			return has_value() ? other.has_value() && value() == other.value() : !other.has_value();
		}
		template<typename R = decltype( std::declval<const T&>() != std::declval<const T&>() )>
		R operator!=( const optional_reference& other ) const
		{
			return has_value() ? !other.has_value() || value() != other.value() : other.has_value();
		}
		template<typename R = decltype( std::declval<const T&>() <= std::declval<const T&>() )>
		R operator<=( const optional_reference& other ) const
		{
			return has_value() ? other.has_value() && value() <= other.value() : true;
		}
		template<typename R = decltype( std::declval<const T&>() < std::declval<const T&>() )>
		R operator<( const optional_reference& other ) const
		{
			return has_value() ? other.has_value() && value() < other.value() : other.has_value();
		}
	};

	// Creates an optional reference to the given pointer if the condition is met.
	//
	template<typename T>
	static auto dereference_if( bool condition, T ptr )
	{
		return condition ? optional_reference( *ptr ) : std::nullopt;
	}

	template<typename T>
	static auto dereference_if_n( bool condition, T ptr, size_t idx )
	{
		return condition ? optional_reference{ *( ptr + idx ) } : std::nullopt;
	}
};

// Overload hashers for vtil::optional_reference<>.
//
namespace vtil
{
	// Same implementation as vtil::hasher<std::optional<T>>.
	//
	template<typename T>
	struct hasher<optional_reference<T>>
	{
		hash_t operator()( const optional_reference<T>& value ) const noexcept
		{
			if ( value ) return make_hash( *value );
			else         return lt_typeid<T>::value;
		}
	};
};
namespace std
{
	// Same implementation as std::hash<std::optional<T>>.
	//
	template<typename T>
	struct hash<vtil::optional_reference<T>>
	{
		size_t operator()( const vtil::optional_reference<T>& value ) const noexcept
		{
			return value ? std::hash<T>{}( *value ) : 0;
		}
	};
};