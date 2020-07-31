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
#include <type_traits>
#include <optional>
#include <utility>
#include "operators.hpp"
#include "bitwise.hpp"

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
    struct operable_tag {};

    // Declare base operable type.
    //
    template<typename base_type>
    struct operable : operable_tag
    {
        // Value of the operand.
        //
        math::bit_vector value = {};

        // Default constructor and the constructor for constant values.
        //
        constexpr operable() = default;
        template<Integral T>
        constexpr operable( T value, bitcnt_t bit_count = sizeof( T ) * 8 ) : value( uint64_t( value ), bit_count ) {}

        // Gets the value represented, and nullopt if value has unknown bits.
        //
        template<typename type>
        constexpr std::optional<type> get() const { return value.get<type>(); }
        template<bool as_signed = false, typename type = std::conditional_t<as_signed, int64_t, uint64_t>>
        constexpr std::optional<type> get() const { return value.get<type>(); }

        // Redirect certain helpers to bit_vector.
        //
        constexpr bitcnt_t size() const { return value.size(); }
        constexpr uint64_t known_mask() const { return value.known_mask(); }
        constexpr uint64_t unknown_mask() const { return value.unknown_mask(); }
        constexpr uint64_t known_one() const { return value.known_one(); }
        constexpr uint64_t known_zero() const { return value.known_zero(); }
        constexpr bool is_constant() const { return value.is_known(); }

        // Resizes the constant, must be overriden by the base type to handle unknowns.
        //
        constexpr void resize( bitcnt_t new_size, bool sign_extend = false )
        {
            fassert( value.is_known() );
            value.resize( new_size, sign_extend );
        }
    };

    // Whether the type is a operable instance or not.
    //
    template<typename T>
    static constexpr bool is_custom_operable_v = std::is_base_of_v<operable_tag, T>;
    
    // Whether the type is operable in combination with an operable instance or not.
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
        if constexpr ( is_custom_operable_v<T1> )
            return std::is_integral_v<T2> || std::is_same_v<T1, T2>;

        // If only T2 is a custom operable, T1 needs to be an integral type.
        //
        else if constexpr ( is_custom_operable_v<T2> )
            return std::is_integral_v<T1>;
        return false;
    }

    // Can be overriden externally to allow aliases.
    //
    template<typename T1, typename = void>
    struct resolve_alias { using type = T1; };

    // Removes all qualifiers and resolves the base if aliased.
    //
    template<typename T1>
    using strip_operable_t = typename resolve_alias<std::remove_cvref_t<T1>>::type;

    // Operable concepts.
    //
    template<typename T> concept CustomOperable =     is_custom_operable_v<strip_operable_t<T>>;
    template<typename T> concept Operable =           is_operable_v<strip_operable_t<T>>;

    // Returns the result of the cross-operation between two types, void if not cross-operable.
    //
    template<typename T1, typename T2, typename = void>
    struct xop_result;

    template<typename T1, typename T2>
    struct xop_result<T1, T2, std::enable_if_t<is_xoperable<strip_operable_t<T1>, strip_operable_t<T2>>()>>
    {
        using type = std::conditional_t<
            is_custom_operable_v<strip_operable_t<T1>>,
            strip_operable_t<T1>,
            strip_operable_t<T2>
        >;
    };

    template<typename T1, typename T2>
    static constexpr operator_id operator_hint_sign( operator_id op )
    {
        using T1p = std::remove_cvref_t<T1>;
        using T2p = std::remove_cvref_t<T2>;

        if constexpr ( std::conditional_t<std::is_integral_v<T1p>, std::is_unsigned<T1p>, std::false_type>::value ||
                       std::conditional_t<std::is_integral_v<T2p>, std::is_unsigned<T2p>, std::false_type>::value )
        {
            switch ( op )
            {
                case operator_id::greater:       return operator_id::ugreater;
                case operator_id::greater_eq:    return operator_id::ugreater_eq;
                case operator_id::equal:         return operator_id::uequal;
                case operator_id::not_equal:     return operator_id::unot_equal;
                case operator_id::less_eq:       return operator_id::uless_eq;
                case operator_id::less:          return operator_id::uless;
                case operator_id::multiply_high: return operator_id::umultiply_high;
                case operator_id::multiply:      return operator_id::umultiply;
                case operator_id::divide:        return operator_id::udivide;
                case operator_id::remainder:     return operator_id::uremainder;
                case operator_id::min_value:     return operator_id::umin_value;
                case operator_id::max_value:     return operator_id::umax_value;
                default: break;
            }
        }
        return op;
    }

    // Declare a common building point for operables so that they can be hooked on demand.
    //
    template<typename R, Operable T1, Operable T2>
    __forceinline static constexpr R make_operable( T1&& a, math::operator_id op, T2&& b ) { return R{ std::forward<T1>( a ), op, std::forward<T2>( b ) }; }
    template<typename R, Operable T1>
    __forceinline static constexpr R make_operable( math::operator_id op, T1&& a ) { return R{ op, std::forward<T1>( a ) }; }
};

#undef __max // Seriously stdlib?
#undef __min

// Evaluation operations with operable types.
//
#define DEFINE_EVAL(...)					    															                        \
template<vtil::math::Operable T1, vtil::math::Operable T2 = int, typename R = typename vtil::math::xop_result<T1, T2>::type>	\
static constexpr R __VA_ARGS__

// Assignment operations with operable types.
// - Result type is not used but left there to assert cross-operableness as an enable_if.
//
#define DEFINE_ASGN( assn_op, eval_op )                                                                                             \
template<vtil::math::CustomOperable T1, vtil::math::Operable T2 = int, typename = typename vtil::math::xop_result<T1, T2>::type>    \
static constexpr T1& assn_op ( T1& op, T2&& param ) { return ( op = eval_op ( std::move( op ), std::forward<T2>( param ) ) ); }                

DEFINE_EVAL( operator~( T1&& a )                { return vtil::math::make_operable<R>( vtil::math::operator_id::bitwise_not, std::forward<T1>( a ) ); }                                                                );
DEFINE_EVAL( operator&( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::bitwise_and, std::forward<T2>( b ) ); }                                         );
DEFINE_EVAL( operator|( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::bitwise_or, std::forward<T2>( b ) ); }                                          );
DEFINE_EVAL( operator^( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::bitwise_xor, std::forward<T2>( b ) ); }                                         );
DEFINE_EVAL( operator>>( T1&& a, T2&& b )       { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::shift_right, std::forward<T2>( b ) ); }                                         );
DEFINE_EVAL( operator<<( T1&& a, T2&& b )       { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::shift_left, std::forward<T2>( b ) ); }                                          );
DEFINE_EVAL( __rotr( T1&& a, T2&& b )           { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::rotate_right, std::forward<T2>( b ) ); }                                        );
DEFINE_EVAL( __rotl( T1&& a, T2&& b )           { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::rotate_left, std::forward<T2>( b ) ); }                                         );
DEFINE_EVAL( operator-( T1&& a )                { return vtil::math::make_operable<R>( vtil::math::operator_id::negate, std::forward<T1>( a ) ); }                                                                     );
DEFINE_EVAL( operator+( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::add, std::forward<T2>( b ) ); }                                                 );
DEFINE_EVAL( operator-( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::subtract, std::forward<T2>( b ) ); }                                            );
DEFINE_EVAL( mulhi( T1&& a, T2&& b )            { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::multiply_high), std::forward<T2>( b ) ); });
DEFINE_EVAL( operator*( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::multiply), std::forward<T2>( b ) ); }     );
DEFINE_EVAL( operator/( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::divide), std::forward<T2>( b ) ); }       );
DEFINE_EVAL( operator%( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::remainder), std::forward<T2>( b ) ); }    );
DEFINE_EVAL( umulhi( T1&& a, T2&& b )           { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::umultiply_high, std::forward<T2>( b ) ); }                                      );
DEFINE_EVAL( umul( T1&& a, T2&& b )             { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::umultiply, std::forward<T2>( b ) ); }                                           );
DEFINE_EVAL( udiv( T1&& a, T2&& b )             { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::udivide, std::forward<T2>( b ) ); }                                             );
DEFINE_EVAL( urem( T1&& a, T2&& b )             { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::uremainder, std::forward<T2>( b ) ); }                                          );
DEFINE_EVAL( __ucast( T1&& a, T2&& b )          { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::ucast, std::forward<T2>( b ) ); }                                               );
DEFINE_EVAL( __cast( T1&& a, T2&& b )           { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::cast, std::forward<T2>( b ) ); }                                                );
DEFINE_EVAL( __popcnt( T1&& a )                 { return vtil::math::make_operable<R>( vtil::math::operator_id::popcnt, std::forward<T1>( a ) ); }                                                                     );
DEFINE_EVAL( __bsf( T1&& a )                    { return vtil::math::make_operable<R>( vtil::math::operator_id::bitscan_fwd, std::forward<T1>( a ) ); }                                                                );
DEFINE_EVAL( __bsr( T1&& a )                    { return vtil::math::make_operable<R>( vtil::math::operator_id::bitscan_rev, std::forward<T1>( a ) ); }                                                                );
DEFINE_EVAL( __bt( T1&& a, T2&& b )             { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::bit_test, std::forward<T2>( b ) ); }                                            );
DEFINE_EVAL( __mask( T1&& a )                   { return vtil::math::make_operable<R>( vtil::math::operator_id::mask, std::forward<T1>( a ) ); }                                                                       );
DEFINE_EVAL( __bcnt( T1&& a )                   { return vtil::math::make_operable<R>( vtil::math::operator_id::bit_count, std::forward<T1>( a ) ); }                                                                  );
DEFINE_EVAL( __if( T1&& a, T2&& b )             { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::value_if, std::forward<T2>( b ) ); }                                            );
DEFINE_EVAL( __max( T1&& a, T2&& b )            { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::max_value), std::forward<T2>( b ) ); }    );
DEFINE_EVAL( __min( T1&& a, T2&& b )            { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::min_value), std::forward<T2>( b ) ); }    );
DEFINE_EVAL( __umax( T1&& a, T2&& b )           { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::umax_value, std::forward<T2>( b ) ); }                                          );
DEFINE_EVAL( __umin( T1&& a, T2&& b )           { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::umin_value, std::forward<T2>( b ) ); }                                          );
DEFINE_EVAL( operator>( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::greater), std::forward<T2>( b ) ); }      );
DEFINE_EVAL( operator>=( T1&& a, T2&& b )       { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::greater_eq), std::forward<T2>( b ) ); }   );
DEFINE_EVAL( operator==( T1&& a, T2&& b )       { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::equal), std::forward<T2>( b ) ); }        );
DEFINE_EVAL( operator!=( T1&& a, T2&& b )       { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::not_equal), std::forward<T2>( b ) ); }    );
DEFINE_EVAL( operator<=( T1&& a, T2&& b )       { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::less_eq), std::forward<T2>( b ) ); }      );
DEFINE_EVAL( operator<( T1&& a, T2&& b )        { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_hint_sign<T1,T2>(vtil::math::operator_id::less), std::forward<T2>( b ) ); }         );
DEFINE_EVAL( __ugreat( T1&& a, T2&& b )         { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::ugreater, std::forward<T2>( b ) ); }                                            );
DEFINE_EVAL( __ugreat_eq( T1&& a, T2&& b )      { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::ugreater_eq, std::forward<T2>( b ) ); }                                         );
DEFINE_EVAL( __uequal( T1&& a, T2&& b )         { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::uequal, std::forward<T2>( b ) ); }                                              );
DEFINE_EVAL( __unot_equal( T1&& a, T2&& b )     { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::unot_equal, std::forward<T2>( b ) ); }                                          );
DEFINE_EVAL( __uless_eq( T1&& a, T2&& b )       { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::uless_eq, std::forward<T2>( b ) ); }                                            );
DEFINE_EVAL( __uless( T1&& a, T2&& b )          { return vtil::math::make_operable<R>( std::forward<T1>( a ), vtil::math::operator_id::uless, std::forward<T2>( b ) ); }                                               );
DEFINE_ASGN( operator>>=, operator>> );
DEFINE_ASGN( operator<<=, operator<< );
DEFINE_ASGN( operator+=,  operator+ );
DEFINE_ASGN( operator-=,  operator- );
DEFINE_ASGN( operator|=,  operator| );
DEFINE_ASGN( operator&=,  operator& );
DEFINE_ASGN( operator^=,  operator^ );
DEFINE_ASGN( operator*=,  operator* );
DEFINE_ASGN( operator/=,  operator/ );
DEFINE_ASGN( operator%=,  operator% );

#undef DEFINE_ASGN
#undef DEFINE_EVAL