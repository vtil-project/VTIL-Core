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
#include "../directives/directive.hpp"

namespace vtil::symbolic::directive
{
    // List of universal simplifiers, they have to reduce complexity or keep it equal
    // at the very least to not cause an infinity loop.
    //
    static constexpr std::tuple universal_simplifiers =
    {
        // TODO: Arithmetic operators, */% etc.
        //

        // Double inverse.
        //
        std::pair{ -(-A),                                              A },
        std::pair{ ~(~A),                                              A },
        std::pair{ -(~A),                                              A+1 },
        std::pair{ ~(-A),                                              A-1 },

        // Identity constants.
        //
        std::pair{ A + 0,                                              A },
        std::pair{ A - 0,                                              A },
        std::pair{ A | A,                                              A },
        std::pair{ A|0,                                                A },
        std::pair{ A&A,                                                A },
        std::pair{ A^0,                                                A },
        std::pair{ A&-1,                                               A },
        std::pair{ A*1,                                                A },
        std::pair{ A*1u,                                               A },
        std::pair{ A/1,                                                A },
        std::pair{ A/1u,                                               A },
        std::pair{ __rotl(A,0),                                        A },
        std::pair{ __rotr(A,0),                                        A },
        std::pair{ A>>0,                                               A },
        std::pair{ A<<0,                                               A },
        std::pair{ A==1,                                               __iff(__bcnt(A)==1u, A) },
        std::pair{ A!=0,                                               __iff(__bcnt(A)==1u, A) },

        // Constant result.
        //
        std::pair{ A-A,                                                instance{ 0 } },
        std::pair{ A+(-A),                                             instance{ 0 } },
        std::pair{ A&0,                                                instance{ 0 } },
        std::pair{ A^A,                                                instance{ 0 } },
        std::pair{ A&(~A),                                             instance{ 0 } },
        std::pair{ A|-1,                                               instance{ -1 } },
        std::pair{ A+(~A),                                             instance{ -1 } },
        std::pair{ A^(~A),                                             instance{ -1 } },
        std::pair{ A|(~A),                                             instance{ -1 } },
        std::pair{ A/A,                                                instance{ 1 } },
        std::pair{ udiv(A,A),                                          instance{ 1 } },
        std::pair{ A%A,                                                instance{ 0 } },
        std::pair{ urem(A,A),                                          instance{ 0 } },
        std::pair{ A*0,                                                instance{ 0 } },
        std::pair{ A*0u,                                               instance{ 0 } },
        //std::pair{ A>>B,                                             __iff(B>=__bcnt(A), 0) },     [Removed as partial evaluator will take care of this]
        //std::pair{ A<<B,                                             __iff(B>=__bcnt(A), 0) },     [Removed as partial evaluator will take care of this]

        // SUB conversion.
        //
        std::pair{ A+(-B),                                             A-B },
        std::pair{ ~((~A)+B),                                          A-B },
        std::pair{ ~(A-B),                                             (~A)+B },
        std::pair{ (~A+U),                                             (U-1)-A },

        // NEG conversion.
        //
        std::pair{ ~(A-1),                                             -A },
        std::pair{ 0-A,                                                -A },

        // MUL conversion.
        //
        std::pair{ A+A,                                                A*2 },
        std::pair{ A*U-A,                                              A*(U-1) },
        std::pair{ A*U+A,                                              A*(U+1) },

        // Invert comparison.
        //
        std::pair{ ~(A>B),                                             A<=B },
        std::pair{ ~(A>=B),                                            A<B },
        std::pair{ ~(A==B),                                            A!=B },
        std::pair{ ~(A!=B),                                            A==B },
        std::pair{ ~(A<=B),                                            A>B },
        std::pair{ ~(A<B),                                             A>=B },
        std::pair{ ~__ugreat(A,B),                                     __uless_eq(A,B) },
        std::pair{ ~__ugreat_eq(A,B),                                  __uless(A,B) },
        std::pair{ ~__uless(A,B),                                      __ugreat_eq(A,B) },
        std::pair{ ~__uless_eq(A,B),                                   __ugreat(A,B) },

        // NOT conversion.
        //
        std::pair{ A^-1,                                               ~A },
        std::pair{ A==0,                                               __iff(__bcnt(A)==1u, A^1) },
        std::pair{ A!=1,                                               __iff(__bcnt(A)==1u, A^1) },

        // XOR conversion.
        //
        std::pair{ (A|B)&(~(A&B)),                                     A^B },
        std::pair{ (A|B)&((~A)|(~B)),                                  A^B },
        std::pair{ (A&(~B))|((~A)&B),                                  A^B },
        std::pair{ (~(A|B))|(A&B),                                     ~(A^B) },
        std::pair{ ((~A)&(~B))|(A&B),                                  ~(A^B) },

        // Simplify AND OR NOT XOR.
        //
        std::pair{ A&(A|B),                                            A },
        std::pair{ A|(A&B),                                            A },
        std::pair{ A^(A&B),                                            A&~B },
        std::pair{ A^(A|B),                                            B&~A },

        // Simplify rotation count.
        //
        std::pair{ __rotl(A,U),                                        __iff(U>=__bcnt(A), __rotl(A,!(U%__bcnt(A)))) },
        std::pair{ __rotr(A,U),                                        __iff(U>=__bcnt(A), __rotr(A,!(U%__bcnt(A)))) },

        // Convert SHL|SHR and OR combinations to rotate.
        //
        std::pair{ (A>>B)|(A<<C),                                      __iff(C==(__bcnt(A)-B), __rotr(A,B)) },
        std::pair{ (A<<B)|(A>>C),                                      __iff(C==(__bcnt(A)-B), __rotl(A,B)) },

        // Drop unnecessary casts.
        //
        std::pair{ __ucast(A,B),                                       __iff(__bcnt(A)==B, A) },
        std::pair{ __cast(A,B),                                        __iff(__bcnt(A)==B, A) },

        // Simplify SHL|SHR and ROTL|ROTR.
        //
        //std::pair{ __ucast(A,B)>>U,                                    __iff((__mask(A)>>U)==0, 0) },              [Removed as partial evaluator will take care of this]
        //std::pair{ __cast(A,B)>>U,                                     __iff((__mask(A)>>U)==0, -1>>U) },          [Removed as partial evaluator will take care of this]
        //std::pair{ __ucast(A,B)<<U,                                    __iff((__mask(A)<<U)==0, 0) },              [Removed as partial evaluator will take care of this]
        std::pair{ __cast(A,B)<<U,                                     __iff(U>((B*8)-__bcnt(A)), __ucast(A,B)<<U) },

        // Simplify AND/OR/NOT combinations.
        //
        std::pair{ (~A)&(~B),                                          ~(A|B) },
        std::pair{ (~A)|(~B),                                          ~(A&B) },
        std::pair{ ~(U&A),                                             !(~U)|s(~A) },
        std::pair{ ~(U|A),                                             !(~U)&s(~A) },
        std::pair{ (A&B)|(A&C),                                        A&(B|C) },
        std::pair{ (A|B)&(A|C),                                        A|(B&C) },

        // -- Special AND OR directives to reduce unknown:
        //
        std::pair{ U|B,                                                __iff(U==(__mask_knw1(B)), B) },
        std::pair{ U|B,                                                __iff(((~__mask_knw0(B))&(~U))==0u,  U) },
        std::pair{ U&B,                                                __iff(U==(__mask_unk(B)|__mask_knw1(B)), B) },
        std::pair{ U&B,                                                __iff(((~__mask_knw0(B))&U)==0u,  0) },

        // Penetrate shrinked expression with shift left.
        // - This is an exceptional case and has to be addressed due to the fact
        //   that when (A>>C) is shrinked, the cast cannot propagate down to A
        //   and unless we add this rule to try simplifying after penetrating it
        //   it cannot escape the cast and simplify with the newly added shift.
        //
        std::pair{ __ucast(A,B)<<U,                                    __iff(__bcnt(A)>B,    __ucast(!(A<<U), B) ) },

        // Merge ucast combinations.
        //
        std::pair{ __ucast(A,U)|__ucast(B,U),                          __iff(__bcnt(A)>=__bcnt(B), __ucast(!(A|B),U)) },
        std::pair{ __ucast(A,U)&__ucast(B,U),                          __iff(__bcnt(A)>=__bcnt(B), __ucast(!(A&B),U)) },
        std::pair{ __ucast(A,U)^__ucast(B,U),                          __iff(__bcnt(A)>=__bcnt(B), __ucast(!(A^B),U)) },

        // Simplify manual sign extension.
        //
        std::pair{ __ucast(A,B)|(__ucast((0x1+~(A>>U)), B)<<C),       __iff((B>__bcnt(A))&(U==(__bcnt(A)-1))&(C==__bcnt(A))&(__bcnt(A)!=1), __cast(A,B)) },
        std::pair{ __ucast(A,B)|((~(__ucast(A,B)>>U)+0x1)<<C),        __iff((B>__bcnt(A))&(U==(__bcnt(A)-1))&(C==__bcnt(A))&(__bcnt(A)!=1), __cast(A,B)) },
        std::pair{ (((((~(A>>B))|-0x2)+0x1)<<U)|A),                   __iff((U==(B+1))&(__bcnt(A)!=1), __cast(__ucast(A,U),__bcnt(A))) },
    };

    // Describes the way operands of two operators join each other.
    // - Has no obligation to produce simple output, should be checked.
    //
    static constexpr std::tuple join_descriptors =
    {
        // TODO: Arithmetic operators, */% etc.
        // TODO: Should we add ADD and SUB to bitwise despite the partial evaluator?
        //

        // -- Special AND OR directives to reduce unknown:
        //
        std::pair{ A|B,                                                __iff((__mask_knw1(A)&__mask_unk(B))!=0u, A|!(B&!(~__mask_knw1(A))))},
        std::pair{ A&B,                                                __iff((__mask_knw0(A)&~__mask_knw0(B))!=0u, A&!(B&!(~__mask_knw0(A))))},

        // -- Special OR substitute to ADD:
        //
        std::pair{ A+B,                                                __iff(((__mask_knw1(A)|__mask_unk(A))&(__mask_knw1(B)|__mask_unk(B)))==0u, A|B)},

        // ADD:
        //
        std::pair{ A+(B+C),                                            !(A+B)+C },
        std::pair{ A+(B-C),                                            !(A+B)-C },
        std::pair{ A+(B-C),                                            !(A-C)+B },

        // SUB:
        //
        std::pair{ A-(B+C),                                            !(A-B)-C },
        std::pair{ A-(B-C),                                            !(A+C)-B },
        std::pair{ A-(B-C),                                            !(A-B)+C },
        std::pair{ (B+C)-A,                                            !(B-A)+C },
        std::pair{ (B-C)-A,                                            B-!(A+C) },
        std::pair{ (B-C)-A,                                            !(B-A)-C },

        // OR:
        //
        std::pair{ A|(B|C),                                            !(A|B)|!(A|C) },
        std::pair{ A|(B|C),                                            !(A|B)|__or(!(A|C), C) },
        std::pair{ A|(B&C),                                            !(A|B)&!(A|C) },
        std::pair{ A|(B&C),                                            A|(!(A|B)&C) },
        std::pair{ A|(B^C),                                            A|s(!(B&s(~A))^s(C&(~A))) },
        std::pair{ A|(B<<U),                                           !(!(A>>U)|B)<<U|s(A&((1<<U)-1)) },
        std::pair{ A|(B>>U),                                           !(!(A<<U)|B)>>U|s(A&(~((-1<<U)>>U))) },
        std::pair{ A|(__rotl(B,C)),                                    __rotl(!(B|s(__rotr(A,C))), C) },
        std::pair{ A|(__rotr(B,C)),                                    __rotr(!(B|s(__rotl(A,C))), C) },
        std::pair{ A|~B,                                               ~!(B&s(~A)) },

        // AND:
        //
        std::pair{ A&(B|C),                                            !(A&B)|!(A&C) },
        std::pair{ A&(B|C),                                            A&s(!(A&B)|C) },
        std::pair{ A&(B&C),                                            !(A&B)&!(A&C) },
        std::pair{ A&(B&C),                                            !(A&B)&__or(!(A&C),C) },
        std::pair{ A&(B^C),                                            !(A&B)^!(A&C) },
        std::pair{ A&(B^C),                                            A&s(!(A&B)^C) },
        std::pair{ A&(B<<U),                                           !(!(A>>U)&B)<<U },
        std::pair{ A&(B>>U),                                           !(!(A<<U)&B)>>U },
        std::pair{ A&(__rotl(B,C)),                                    __rotl(!(B&s(__rotr(A,C))), C) },
        std::pair{ A&(__rotr(B,C)),                                    __rotr(!(B&s(__rotl(A,C))), C) },
        std::pair{ A&~B,                                               ~!(B|s(~A)) },

        // XOR:
        //
        std::pair{ A^(B&C),                                            s(A|(B&C))&s(~(B&!(A&C))) },
        std::pair{ A^(B|C),                                            s(B|!(A|C))&s(~(A&(B|C))) },
        std::pair{ A^(B^C),                                            B^!(A^C) },
        std::pair{ A^(B<<U),                                           !(!(A>>U)^B)<<U|s(A&((1<<U)-1)) },
        std::pair{ A^(B>>U),                                           !(!(A<<U)^B)>>U|s(A&(~((-1<<U)>>U))) },
        std::pair{ A^(__rotl(B,C)),                                    __rotl(!(B^s(__rotr(A,C))), C) },
        std::pair{ A^(__rotr(B,C)),                                    __rotr(!(B^s(__rotl(A,C))), C) },
        std::pair{ A^~B,                                               !(~A)^B },

        // SHL:
        //
        std::pair{ (A|B)<<C,                                           !(A<<C)|s(B<<C) },
        std::pair{ (A&B)<<C,                                           !(A<<C)&s(B<<C) },
        std::pair{ (A^B)<<C,                                           !(A<<C)^s(B<<C) },
        std::pair{ (A<<B)<<C,                                          A<<!(B+C) },
        std::pair{ (A>>B)<<C,                                          __iff(B>=C, !((-1>>B)<<C)&(A>>!(B-C))) },
        std::pair{ (A>>C)<<B,                                          __iff(B>=C, !((-1>>C)<<B)&(A<<!(B-C))) },
        // Missing: __rotl, __rotr
        std::pair{ (~A)<<U,                                            (~(A<<U))&(-1<<U) },

        // SHR:
        //
        std::pair{ (A|B)>>C,                                           !(A>>C)|s(B>>C) },
        std::pair{ (A&B)>>C,                                           !(A>>C)&s(B>>C) },
        std::pair{ (A^B)>>C,                                           !(A>>C)^s(B>>C) },
        std::pair{ (A<<C)>>B,                                          __iff(B>=C, !((-1<<C)>>B)&(A>>!(B-C))) },
        std::pair{ (A<<B)>>C,                                          __iff(B>=C, !((-1<<B)>>C)&(A<<!(B-C))) },
        std::pair{ (A>>B)>>C,                                          A>>!(B+C) },
        // Missing: __rotl, __rotr
        std::pair{ (~A)>>U,                                            (~(A>>U))&(-1>>U) },

        // ROL:
        //
        std::pair{ __rotl(A|B,C),                                      __rotl(A,C)|__rotl(B,C) },
        std::pair{ __rotl(A&B,C),                                      __rotl(A,C)&__rotl(B,C) },
        std::pair{ __rotl(A^B,C),                                      __rotl(A,C)^__rotl(B,C) },
        // Missing: shl, shr
        std::pair{ __rotl(__rotl(A,B),C),                              __rotl(A,!(B+C)) },
        std::pair{ __rotl(__rotr(A,B),C),                              __iff(B>=C, __rotr(A,!(B-C))) },
        std::pair{ __rotl(__rotr(A,C),B),                              __iff(B>=C, __rotl(A,!(B-C))) },
        std::pair{ __rotl(~A,C),                                       ~__rotl(A,C) },

        // ROR:
        //
        std::pair{ __rotr(A|B,C),                                      __rotr(A,C)|__rotr(B,C) },
        std::pair{ __rotr(A&B,C),                                      __rotr(A,C)&__rotr(B,C) },
        std::pair{ __rotr(A^B,C),                                      __rotr(A,C)^__rotr(B,C) },
        // Missing: shl, shr
        std::pair{ __rotr(__rotl(A,B),C),                              __iff(B>=C, __rotl(A,(B-C))) },
        std::pair{ __rotr(__rotl(A,C),B),                              __iff(B>=C, __rotr(A,(B-C))) },
        std::pair{ __rotr(__rotr(A,B),C),                              __rotr(A,(B+C)) },
        std::pair{ __rotr(~A,C),                                       ~__rotr(A,C) },

        // NOT:
        //
        std::pair{ ~(A|B),                                             !(~A)&s(~B)  },
        std::pair{ ~(A&B),                                             !(~A)|s(~B)  },
        std::pair{ ~(A^B),  !(~A)^B  },
        // Missing: shl, shr
        std::pair{ ~__rotl(A,C),                                       __rotl(!~A,C) },
        std::pair{ ~__rotr(A,C),                                       __rotr(!~A,C) },

        // Lower immediate urem/udiv/mul into and/shr/shl where possible.
        //
        std::pair{ A*U,                                                __iff(__popcnt(U)==1, A<<!(__bsf(U)-1)) },
        std::pair{ A+(A<<U),                                           A*!(1 + (1<<U)) },
        std::pair{ urem(A,U),                                          __iff(__popcnt(U)==1, A&!(U-1)) },
        std::pair{ udiv(A,U),                                          __iff(__popcnt(U)==1, A>>!(__bsf(U)-1)) },

        // Manually added comparison simplifiers:
        //
        std::pair{ (A<<B)==C,                                          s((A<<B)>>B)==s(C>>B) },
        std::pair{ (A>>B)==C,                                          s((A>>B)<<B)==s(C<<B) },
        std::pair{ ((A<<B)|C)==0,                                      __iff(A==((A<<B)>>B), (A|C)==0u ) },
        std::pair{ (A|B)==0,                                           s(A==0) & s(B==0) },
        std::pair{ __ucast(A,B)==C,                                    __iff(__bcnt(A)<=__bcnt(C), __iff(C==__ucast(C,__bcnt(A)), A==s(__ucast(C,__bcnt(A))))) },
        std::pair{ __ucast(A,B)==C,                                    __iff(__bcnt(A)<=__bcnt(C), __iff(C!=__ucast(C,__bcnt(A)), 0)) },
    };

    // Grouping of simple representations into more complex directives.
    //
    static constexpr std::tuple pack_descriptors =
    {
        std::pair{ __ucast(A>>B, 0x1),                                 __bt(A, B) },
        std::pair{ (A>>B)&1,                                           __ucast(__bt(A,B),__bcnt(A)) },
        std::pair{ (A&B)>>C,                                           __iff((B>>C)==1u, __ucast(__bt(A,C),__bcnt(A))) },
        std::pair{ __if(A<=B,A)|__if(A>B,B),                           __min(A,B) },
        std::pair{ __if(A<=B,A)+__if(A>B,B),                           __min(A,B) },
        std::pair{ __if(A>=B,A)|__if(A<B,B),                           __max(A,B) },
        std::pair{ __if(A>=B,A)+__if(A<B,B),                           __max(A,B) },
        std::pair{ __if(__uless_eq(A,B),A)|__if(__ugreat(A,B),B),      __umin(A,B) },
        std::pair{ __if(__uless_eq(A,B),A)+__if(__ugreat(A,B),B),      __umin(A,B) },
        std::pair{ __if(__ugreat_eq(A,B),A)|__if(__uless(A,B),B),      __umax(A,B) },
        std::pair{ __if(__ugreat_eq(A,B),A)+__if(__uless(A,B),B),      __umax(A,B) },
        std::pair{ (~(A+(-1)))&B,                                      __iff((__mask_unk(A)|__mask_knw1(A))==1u, __if(s(__ucast(A,1)),B)) },
        std::pair{ (~(A-1))&B,                                         __iff((__mask_unk(A)|__mask_knw1(A))==1u, __if(s(__ucast(A,1)),B)) },
        std::pair{ ((A+(-1)))&B,                                       __iff((__mask_unk(A)|__mask_knw1(A))==1u, __if(s(__ucast(~A,1)),B)) },
        std::pair{ ((A-1))&B,                                          __iff((__mask_unk(A)|__mask_knw1(A))==1u, __if(s(__ucast(~A,1)),B)) },
    };

    // Conversion from more complex directives into simple representations.
    //
    static constexpr std::tuple unpack_descriptors =
    {
        std::pair{ __bt(A,B),                                          __ucast((A&(1<<B))>>B,1) },
        std::pair{ __min(A,B),                                         __if(A<=B,A)|__if(A>B,B) },
        std::pair{ __max(A,B),                                         __if(A>=B,A)|__if(A<B,B) },
        std::pair{ __umin(A,B),                                        __if(__uless_eq(A,B),A)|__if(__ugreat(A,B),B) },
        std::pair{ __umax(A,B),                                        __if(__ugreat_eq(A,B),A)|__if(__uless(A,B),B) },
        std::pair{ __if(~A,B),                                         (((__ucast(A,__bcnt(B))&1)-1))&B },
        std::pair{ __if(A,B),                                          (~((__ucast(A,__bcnt(B))&1)-1))&B },
    };

    static const dynamic_directive_table& get_pack_descriptors( math::operator_id op ) { static auto tbl = create_dynamic_table( pack_descriptors ); return tbl[( size_t ) op] ; }
    static const dynamic_directive_table& get_join_descriptors( math::operator_id op ) { static auto tbl = create_dynamic_table( join_descriptors ); return tbl[ ( size_t ) op ]; }
    static const dynamic_directive_table& get_unpack_descriptors( math::operator_id op ) { static auto tbl = create_dynamic_table( unpack_descriptors ); return tbl[ ( size_t ) op ]; }
    static const dynamic_directive_table& get_universal_simplifiers( math::operator_id op ) { static auto tbl = create_dynamic_table( universal_simplifiers ); return tbl[ ( size_t ) op ]; }
};