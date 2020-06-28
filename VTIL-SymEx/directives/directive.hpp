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
#include <vtil/math>
#include <vtil/utility>
#include <type_traits>
#include <unordered_set>

namespace vtil::symbolic::directive
{
    // Directive variables with mathching constraints:
    //
    enum matching_type
    {
        // None.
        match_any,

        // Must be a variable.
        match_variable,
        
        // Must be a constant.
        match_constant,
        
        // Must be a full-expression.
        match_expression,
        
        // Must be anything but a full-expression.
        match_non_expression,

        // Must be anything but a constant (including those that are not folded into a constant yet).
        match_non_constant,
    };

    // Directive operators
    // - Using a struct tagged enum instead of enum class to let's us define 
    //   custom cast operators, constructors and member functions by allowing
    //   by allowing implicit conversion between them.
    //
    //
    struct directive_op_desc
    {
        static constexpr uint8_t begin_id = 1 + ( uint8_t ) math::operator_id::max;
        enum _tag
        {
        min,
            // Simplification Controller
            // -------------------------
            // - !x, indicates that x must be simplified for this directive to be valid.
            simplify,
            // - s(x), indicates that x should be passed through simplifier.
            try_simplify,

            // Conditional
            // -----------
            // - __iff(a,b), returns b if a holds, otherwise invalid.
            iff,
            // - __or(a,b), picks a if valid, otherwise b. Similar to __unpack in that sense, but does not
            //   propagate the chosen index.
            or_also,

            // State-Accessor.
            // ---------------
            // - __mask_unk(x), will generate the mask for unknown bits.
            mask_unknown,
            // - __mask_unk(x), will generate the mask for known one bits.
            mask_one,
            // - __mask_unk(x), will generate the mask for known zero bits.
            mask_zero,


            // Evaluation-time Message
            // -----------------------
            // - __unreachable(), indicates that this directive should never be matched and if it is,
            //   simplifier logic has a bug which should be fixed, acts as a debugging/validation tool.
            unreachable,
            // - __warning(), indicates that this directive should generate a warning.
            warning,
        max,
        } value = min;

        // Default constructor / move / copy.
        //
        directive_op_desc() = default;
        directive_op_desc( directive_op_desc&& ) = default;
        directive_op_desc( const directive_op_desc& ) = default;
        directive_op_desc& operator=( directive_op_desc&& ) = default;
        directive_op_desc& operator=( const directive_op_desc& ) = default;

        // Construct from tagged enum and math::operator_id.
        //
        constexpr directive_op_desc( _tag i ) : value( i ) {}
        directive_op_desc( math::operator_id op ) : value( _tag( ( uint8_t ) op - begin_id ) ) { fassert( min < value && value < max ); }

        // Conversion back to math::operator_id and integer.
        //
        constexpr operator uint8_t() const { return ( uint8_t ) value + begin_id; }
        constexpr operator math::operator_id() const { return math::operator_id( ( uint8_t ) value + begin_id ); }

        // Creates a string representation based on the operands passed.
        //
        std::string to_string( const std::string& lhs, const std::string& rhs ) const
        {
            switch ( value )
            {
                case simplify:      return "{!" + rhs + "}";
                case try_simplify:  return "{try!" + rhs + "}";
                case iff:           return "{" + lhs + " ? " + rhs + "}";
                case or_also:       return "{" + lhs + " <=> " + rhs + "}";
                case mask_unknown:  return "{mask=? " + rhs + "}";
                case mask_one:      return "{mask=1 " + rhs + "}";
                case mask_zero:     return "{mask=0 " + rhs + "}";
                case unreachable:   return "unreachable()";
                case warning:       return "{warning(), " + rhs + "}";
                default:            unreachable();
            }
        }
    };
    template<directive_op_desc::_tag t>
    static constexpr directive_op_desc tagged = t;

    // Operable directive instance, used to describe a simplifier directive.
    //
    struct instance : math::operable<instance>
    {
        using reference = shared_reference<instance>;

        // If symbolic variable, the identifier of the variable
        // and type of expressions it can match.
        //
        const char* id = nullptr;
        matching_type mtype = match_any;
        int lookup_index = 0;

        // The operation we're matching and the operands.
        //
        math::operator_id op = math::operator_id::invalid;
        reference lhs = {};
        reference rhs = {};

        // Default/copy/move constructors.
        //
        instance() {};
        instance( instance&& ) = default;
        instance( const instance& ) = default;
        instance& operator=( instance&& o ) = default;
        instance& operator=( const instance& o ) = default;

        // Variable constructor.
        //
        template<typename T = uint64_t, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        instance( T value ) : operable( int64_t( value ) ) {}
        instance( const char* id, int lookup_index, matching_type mtype = match_any ) : 
            id( id ), lookup_index( lookup_index ), mtype( mtype ) { }

        // Constructor for directive representing the result of an unary operator.
        //
        instance( math::operator_id _op, const instance& e1 );

        // Constructor for directive representing the result of a binary operator.
        //
        instance( const instance& e1, math::operator_id _op, const instance& e2 );

        // Enumerates each unique variable.
        //
        void enum_variables( const std::function<void( const instance& )>& fn, std::unordered_set<const char*>* s = nullptr ) const;

        // Converts to human-readable format.
        //
        std::string to_string() const;

        // Simple equivalence check.
        //
        bool equals( const instance& o ) const;
    };

    /*
       The encoding below must be used when saving this file:
         - Unicode (UTF-8 without signature) - Codepage 65001

       Greek letters are used in simplifier directives as opposed to latin 
       in-order to make the distinction between them painfully obvious.
       
       This really saves you from all the pain of debugging when you "leak"
       a directive variable from the routines, which is why I'm so stubborn
       on using them.


       Used names are kept track using the table below:
       -------------------------------------------------------
       | Free                                 | Used         |
       | ΑΝνΒΞξΓγΟοΔπΕΡρΖσςΗΤτΥυΙιΦφΚκΧχΛψΜμω | ληΠΣΘΩαζβδεΨ |
       -------------------------------------------------------
    */

    // Symbolic variables to be used in rule creation:
    //
    static const instance A = { "α", 0 };
    static const instance B = { "β", 1 };
    static const instance C = { "δ", 2 };
    static const instance D = { "ε", 3 };
    static const instance E = { "ζ", 4 };
    static const instance F = { "η", 5 };
    static const instance G = { "λ", 6 };

    // Special variables, one per type:
    // 
    static const instance V = { "Π", 7, match_variable };
    static const instance U = { "Σ", 8, match_constant };
    static const instance Q = { "Ω", 9, match_expression };
    static const instance W = { "Ψ", 10, match_non_constant };
    static const instance X = { "Θ", 11, match_non_expression };

    // To avoid string comparison each directive variable gets assigned a 
    // lookup table index. This is an arbitrary constant to avoid heap 
    // allocation for the lookup table.
    //
    static constexpr uint32_t number_of_lookup_indices = 12;

    // Operable-like directive operators.
    //
    static instance s( const instance& a ) { return { tagged<directive_op_desc::try_simplify>, a }; }
    static instance operator!( const instance& a ) { return { tagged<directive_op_desc::simplify>, a }; }
    static instance __iff( const instance& a, const instance& b ) { return { a, tagged<directive_op_desc::iff>, b }; }
    static instance __or( const instance& a, const instance& b ) { return { a, tagged<directive_op_desc::or_also>, b }; }
    static instance __unreachable() { return { 0ull, tagged<directive_op_desc::unreachable>, 0ull }; }
    static instance __mask_unk( const instance& a ) { return { tagged<directive_op_desc::mask_unknown>, a }; }
    static instance __mask_knw1( const instance& a ) { return { tagged<directive_op_desc::mask_one>, a }; }
    static instance __mask_knw0( const instance& a ) { return { tagged<directive_op_desc::mask_zero>, a }; }
};

// Implement comparison operators between [directive::directive_op_desc] x [math::operator_id].
//
static bool operator==( vtil::symbolic::directive::directive_op_desc a, vtil::math::operator_id b ) { return uint8_t( b ) > vtil::symbolic::directive::directive_op_desc::begin_id && uint8_t( a ) == uint8_t( b ); }
static bool operator==( vtil::math::operator_id a, vtil::symbolic::directive::directive_op_desc b ) { return uint8_t( a ) > vtil::symbolic::directive::directive_op_desc::begin_id && uint8_t( b ) == uint8_t( a ); }
static bool operator==( vtil::symbolic::directive::directive_op_desc a, vtil::symbolic::directive::directive_op_desc b ) { return a.value == b.value; }
static bool operator!=( vtil::symbolic::directive::directive_op_desc a, vtil::math::operator_id b ) { return uint8_t( b ) <= vtil::symbolic::directive::directive_op_desc::begin_id && uint8_t( a ) != uint8_t( b ); }
static bool operator!=( vtil::math::operator_id a, vtil::symbolic::directive::directive_op_desc b ) { return uint8_t( a ) <= vtil::symbolic::directive::directive_op_desc::begin_id && uint8_t( b ) != uint8_t( a ); }
static bool operator!=( vtil::symbolic::directive::directive_op_desc a, vtil::symbolic::directive::directive_op_desc b ) { return a.value != b.value; }
