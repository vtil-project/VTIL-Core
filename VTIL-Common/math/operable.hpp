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
        // Value of the constant if relevant.
        //
        union
        {
            uint64_t u64 = 0;
            int64_t i64;
        };

        // Whether value is a known constant or not.
        //
        bool is_known = false;

        // Number of bits the value holds.
        //
        uint8_t bit_count = 0;

        // Default constructor and the constructor for constant values.
        //
        operable() = default;
        template<typename T = uint64_t, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        operable( T value, uint8_t bit_count = sizeof( T ) * 8 ) : i64( value ), bit_count( bit_count ), is_known( true ) {}

        // Helper to get (possibly!) the constant value.
        //
        std::optional<int64_t> get( bool as_signed = false ) const 
        { 
            if ( is_known )
                return as_signed ? sign_extend( u64, bit_count ) : zero_extend( u64, bit_count );
            return {}; 
        }

        // Helper to resize the constant, must be overriden by the base type
        // in case we're not resizing a constant.
        //
        void resize( uint8_t new_bit_count, bool sx = false )
        {
            fassert( is_known );
            u64 = sx ? sign_extend( u64, bit_count ) : zero_extend( u64, bit_count );
            u64 &= mask( new_bit_count );
            bit_count = new_bit_count;
        }
    };

    // Whether the type is a operable<?> instance or not.
    //
    template<typename T>
    static constexpr bool is_custom_operable_v = std::is_base_of_v<operable<T>, T>;
    
    // Whether the type is operable in combination with an operable<?> instance or not.
    //
    template<typename T>
    static constexpr bool is_operable_v = std::is_integral_v<T> || is_custom_operable_v<T>;
    
    // Whether given types are cross-operable or not.
    //
    template<typename T1, typename T2 = int>
    static constexpr bool is_xoperable()
    {
        // If T1 is a custom operable, T2 needs to be either an integral type or same type as T1.
        //
        if ( is_custom_operable_v<T1> )
            return std::is_integral_v<T2> || std::is_same_v<T1, T2>;

        // If only T2 is a custom operable, T1 needs to be an integral type.
        //
        else if ( is_custom_operable_v<T2> )
            return std::is_integral_v<T1>;
        return false;
    }

    // Can be overriden externally to allow aliases.
    //
    template<typename T1>
    struct resolve_alias { using type = typename T1; };

    // Removes all qualifiers and resolves the base if aliased.
    //
    template<typename T1>
    using strip_operable_t = typename resolve_alias<std::remove_cvref_t<T1>>::type;

    // Returns the result of the cross-operation between two types, void if not cross-operable.
    //
    template<typename T1, typename T2,
        typename base_type_1 = strip_operable_t<T1>,
        typename base_type_2 = strip_operable_t<T2>,
        std::enable_if_t<is_xoperable<base_type_1, base_type_2>(), int> = 0
    >
    struct xop_result
    {
        using type = std::conditional_t<
            is_custom_operable_v<base_type_1>,
            base_type_1,
            base_type_2
        >;
    };
};

// Operations with operable types
//
#define DEFINE_OPERATION(...)																				\
template<typename T1, typename T2 = T1, typename result_t = typename vtil::math::xop_result<T1, T2>::type>	\
inline static result_t __VA_ARGS__

DEFINE_OPERATION( operator~( T1&& a )				{ return { vtil::math::operator_id::bitwise_not, std::forward<T1>( a ) }; }								);
DEFINE_OPERATION( operator&( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::bitwise_and, std::forward<T2>( b ) }; }		);
DEFINE_OPERATION( operator|( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::bitwise_or, std::forward<T2>( b ) }; }		);
DEFINE_OPERATION( operator^( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::bitwise_xor, std::forward<T2>( b ) }; }		);
DEFINE_OPERATION( operator>>( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::shift_right, std::forward<T2>( b ) }; }		);
DEFINE_OPERATION( operator<<( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::shift_left, std::forward<T2>( b ) }; }		);
DEFINE_OPERATION( __rotr( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::rotate_right, std::forward<T2>( b ) }; }		);
DEFINE_OPERATION( __rotl( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::rotate_left, std::forward<T2>( b ) }; }		);
DEFINE_OPERATION( operator-( T1&& a )				{ return { vtil::math::operator_id::negate, std::forward<T1>( a ) }; }									);
DEFINE_OPERATION( operator+( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::add, std::forward<T2>( b ) }; } 				);
DEFINE_OPERATION( operator-( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::substract, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( imulhi( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::multiply_high, std::forward<T2>( b ) }; }	);
DEFINE_OPERATION( operator*( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::multiply, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( operator/( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::divide, std::forward<T2>( b ) }; } 			);
DEFINE_OPERATION( operator%( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::remainder, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( umulhi( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::umultiply_high, std::forward<T2>( b ) }; } 	);
DEFINE_OPERATION( umul( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::umultiply, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( udiv( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::udivide, std::forward<T2>( b ) }; } 			);
DEFINE_OPERATION( urem( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::uremainder, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( __zx( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::zero_extend, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( __sx( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::sign_extend, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( __popcnt( T1&& a )		        { return { vtil::math::operator_id::popcnt, std::forward<T2>( a ) }; } 			                        );
DEFINE_OPERATION( __msb( T1&& a )			        { return { vtil::math::operator_id::most_sig_bit, std::forward<T2>( a ) }; } 	                        );
DEFINE_OPERATION( __lsb( T1&& a )			        { return { vtil::math::operator_id::least_sig_bit, std::forward<T2>( a ) }; } 	                        );
DEFINE_OPERATION( __bt( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::bit_test, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( __mask( T1&& a )			        { return { vtil::math::operator_id::mask, std::forward<T2>( a ) }; } 			                        );
DEFINE_OPERATION( __bitcnt( T1&& a )		        { return { vtil::math::operator_id::bitcnt, std::forward<T2>( a ) }; } 			                        );
DEFINE_OPERATION( __if( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::value_if, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( operator>( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::greater, std::forward<T2>( b ) }; } 			);
DEFINE_OPERATION( operator>=( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::greater_eq, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( operator==( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::equal, std::forward<T2>( b ) }; } 			);
DEFINE_OPERATION( operator!=( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::not_equal, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( operator<=( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::less_eq, std::forward<T2>( b ) }; } 			);
DEFINE_OPERATION( operator<( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::less, std::forward<T2>( b ) }; } 			);
DEFINE_OPERATION( __ugreat( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::ugreater, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( __ugreat_eq( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::ugreater_eq, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( __uless_eq( T1&& a, T2&& b )		{ return { std::forward<T1>( a ), vtil::math::operator_id::uless_eq, std::forward<T2>( b ) }; } 		);
DEFINE_OPERATION( __uless( T1&& a, T2&& b )			{ return { std::forward<T1>( a ), vtil::math::operator_id::uless, std::forward<T2>( b ) }; } 			);
#undef DEFINE_OPERATION