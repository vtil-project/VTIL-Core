#pragma once
#include <type_traits>
#include <optional>
#include <utility>
#include "operators.hpp"

// Operables provide a very easy way to generate lazy math operators for all 
// [Class x Integer], [Integer x Class], [Class x Class] posibilities as 
// long as the base class provides 2 constructors by contract. 
//
//   template<T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
// - base_class( T value )
//		=> operable( value )
//
// - base_class( operator_desc, const base_class& )                    // For unary operators	(Optionaly T&&)
// - base_class( const base_class&, operator_desc, const base_class& ) // For binary operators	(Optionaly T&&)
//		=> operable(), operable::bit_count must be set at constructor.
//
//
namespace vtil::math
{
	// Declare base operable type.
	//
	template<typename base_type>
	struct operable
	{
		int64_t value = 0;
		uint8_t bit_count = 0;
		bool known = false;

		operable() = default;

		template<typename T = uint64_t, std::enable_if_t<std::is_integral_v<T>, int> = 0>
		operable( T value ) : value( value ), bit_count( sizeof( T ) * 8 ), known( true ) {}
	};

	// Operations with operable types
	//
#define IF_OPERABLE(...)																				\
	template<typename T1, typename T2 = T1, std::enable_if_t<std::is_base_of_v<operable<std::remove_cvref_t<T1>>, std::remove_cvref_t<T1>>, int> = 0>	\
	__VA_ARGS__

	IF_OPERABLE( static auto operator~( T1&& a ) { return T1{ operator_id::bitwise_not, std::forward<T1>( a ) }; } );
	IF_OPERABLE( static auto operator&( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::bitwise_and, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator|( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::bitwise_or, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator^( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::bitwise_xor, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator>>( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::shift_right, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator<<( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::shift_left, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __rotr( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::rotate_right, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __rotl( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::rotate_left, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator-( T1&& a ) { return T1{ operator_id::negate, std::forward<T1>( a ) }; } );
	IF_OPERABLE( static auto operator+( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::add, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator-( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::substract, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto imulhi( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::multiply_high, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator*( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::multiply, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator/( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::divide, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator%( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::remainder, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto umulhi( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::umultiply_high, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto umul( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::umultiply, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto udiv( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::udivide, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto urem( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::uremainder, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __zx( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::zero_extend, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __sx( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::sign_extend, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __popcnt( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::popcnt, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __msb( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::most_sig_bit, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __lsb( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::least_sig_bit, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __bt( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::bit_test, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __mask( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::mask, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __bitcnt( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::bitcnt, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __if( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::value_if, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator>( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::greater, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator>=( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::greater_eq, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator==( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::equal, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator!=( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::not_equal, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator<=( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::less_eq, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto operator<( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::less, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __ugreat( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::ugreater, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __ugreat_eq( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::ugreater_eq, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __uless_eq( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::uless_eq, std::forward<T2>( b ) }; } );
	IF_OPERABLE( static auto __uless( T1&& a, T2&& b ) { return T1{ std::forward<T1>( a ), operator_id::uless, std::forward<T2>( b ) }; } );
#undef IF_OPERABLE
};