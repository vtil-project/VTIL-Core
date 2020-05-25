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
#pragma once
#include <tuple>
#include "hashable.hpp"

// TODO: Remove me.
//  Let modern compilers know that we use these operators as is,
//  implementation considering all candidates would be preferred
//  but since not all of our target compilers implement complete
//  ISO C++20, we have to go with this "patch".
//
#define REDUCABLE_EXPLICIT_INHERIT_CXX20()                      \
    using reducable::operator<;                                 \
    using reducable::operator==;                                \
    using reducable::operator!=;                                

// Reduction macro.
//
#define REDUCE_TO( ... )                                              \
    auto reduce() {                                                   \
        return vtil::reference_as_tuple( __VA_ARGS__ );               \
    }                                                                 \
    auto reduce() const {                                             \
        return vtil::reference_as_tuple( __VA_ARGS__ );               \
    }                                                                 \
    REDUCABLE_EXPLICIT_INHERIT_CXX20()                          

// Reducable types essentially let us do member-type reflection
// which we use to auto generate useful but repetetive methods 
// like ::hash() or comparison operators. Base type has to define
// the following routine where [...] should be replaced by members
// that should be contributing to the comparison/hash operations.
//
// - REDUCE_TO( ... );
//
// - Note: Ideally unique elements that are faster to compare should 
//         come first to speed up the equality comparisons.
//
#pragma warning(push)
#pragma warning(disable: 4305)
namespace vtil
{
    // Forward declaration for optional reference type.
    //
    template<typename T>
    struct optional_reference;

    namespace impl
    {
        // Applies type modifier over each element in pair/tuple.
        //
        template<template<typename> typename F, typename T>
        struct apply_each { using type = F<T>; };
        template<template<typename> typename F, typename... T>
        struct apply_each<F, std::pair<T...>> { using type = std::pair<F<T>...>; };
        template<template<typename> typename F, typename... T>
        struct apply_each<F, std::tuple<T...>> { using type = std::tuple<F<T>...>; };

        template<template<typename> typename F, typename T>
        using apply_each_t = typename apply_each<F, T>::type;

        // Appends a deep const qualifier to each referenced type.
        //
        template<typename T>
        using add_dconst_t = typename std::conditional_t
            <std::is_reference_v<T>,
            std::add_lvalue_reference_t<std::add_const_t<std::remove_reference_t<T>>>,
            std::add_const_t<T>>;

        // Checks if type is optional_reference<T>.
        //
        template <typename T> struct is_optional_reference : std::false_type {};
        template <typename T> struct is_optional_reference<optional_reference<T>> : std::true_type {};
        template <typename T>
        static constexpr bool is_optional_reference_v = is_optional_reference<std::remove_cvref_t<T>>::value;
    };

    // Mask of requested reducable auto declarations.
    //
    enum reducable_auto_decl_id : uint8_t
    {
        reducable_none =     0x00,
        reducable_equ =      1 << 0,
        reducable_nequ =     1 << 1,
        reducable_leq =      1 << 2,
        reducable_greq =     1 << 3,
        reducable_less =     1 << 4,
        reducable_greater =  1 << 5,
        reducable_hash =     1 << 6,
        reducable_all =      0xFF,
    };

    // Reducable tag let's us check if a type is reducable without having 
    // to template for proxied type or the auto-decl flags.
    //
    struct reducable_tag_t {};

    template<typename T>
    static constexpr bool is_reducable_v = std::is_base_of_v<reducable_tag_t, T>;

    // The main definition of the helper:
    //
    template<typename T, uint8_t flags = reducable_all>
    struct reducable : reducable_tag_t
    {
    protected:
        // Invoking T::reduce() in a member function will create problems
        // due to the type not being defined yet, however we can proxy it.
        //
        template<typename Tx>
        static auto reduce_proxy( Tx& p ) { return p.reduce(); }

        template<typename Tx, typename F = decltype( std::declval<Tx>().reduce() )>
        static auto reduce_proxy( const Tx& p )
        {
            return ( typename impl::apply_each_t<impl::add_dconst_t, F> ) reduce_proxy( ( Tx& ) p );
        }

        // Only the base type can construct/copy/move this type.
        //
        reducable() = default;
        reducable( reducable&& ) = default;
        reducable( const reducable& ) = default;
        reducable& operator=( reducable&& ) = default;
        reducable& operator=( const reducable& ) = default;

    public:
        // Define basic comparison operators using std::tuple.
        //
        template<std::enable_if_t<flags&reducable_equ, int> = 0>
        auto operator==( const T& other ) const { return &other == this || reduce_proxy( ( T& ) *this ) == reduce_proxy( other ); }
        template<std::enable_if_t<flags&reducable_nequ, int> = 0>
        auto operator!=( const T& other ) const { return &other != this && reduce_proxy( ( T& ) *this ) != reduce_proxy( other ); }
        template<std::enable_if_t<flags&reducable_leq, int> = 0>
        auto operator<=( const T& other ) const { return &other == this || reduce_proxy( ( T& ) *this ) <= reduce_proxy( other ); }
        template<std::enable_if_t<flags&reducable_greq, int> = 0>
        auto operator>=( const T& other ) const { return &other == this || reduce_proxy( ( T& ) *this ) >= reduce_proxy( other ); }
        template<std::enable_if_t<flags&reducable_less, int> = 0>
        auto operator< ( const T& other ) const { return &other != this && reduce_proxy( ( T& ) *this ) <  reduce_proxy( other ); }
        template<std::enable_if_t<flags&reducable_greater, int> = 0>
        auto operator> ( const T& other ) const { return &other != this && reduce_proxy( ( T& ) *this ) >  reduce_proxy( other ); }

        // Define VTIL hash using a simple VTIL tuple hasher.
        //
        template<std::enable_if_t<flags&reducable_hash, int> = 0>
        hash_t hash() const { return make_hash( reduce_proxy( ( const T& ) *this ) ); }

        // Define the [const T::reduce()] for the base type just for convinience.
        //
        auto reduce() const { return reduce_proxy( ( const T& ) *this ); }
    };

    // Helper used to create reduced tuples.
    //
    template <typename... Tx>
    static constexpr std::tuple<Tx...> reference_as_tuple( Tx&&... args )
    {
        static_assert
        ( 
            std::conjunction_v<
                std::bool_constant<
                    std::is_trivial_v<Tx> || 
                    std::is_reference_v<Tx> || 
                    impl::is_optional_reference_v<Tx>>...>,
            "Reduction function should not pass any non-trivial values by value." 
        );

        return std::tuple<Tx...>( std::forward<Tx>( args )... );
    }
};
#pragma warning(pop)