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
    static const std::pair<instance::reference, instance::reference> universal_simplifiers[] =
    {
        // TODO: Arithmetic operators, */% etc.
        //

        // Double inverse.
        //
        { -(-A),                                              A },
        { ~(~A),                                              A },
        { -(~A),                                              A+1 },
        { ~(-A),                                              A-1 },

        // Identity constants.
        //
        { A+0,                                                A },
        { A-0,                                                A },
        { A|A,                                                A },
        { A|0,                                                A },
        { A&A,                                                A },
        { A^0,                                                A },
        { A&-1,                                               A },
        { A==1,                                               __iff(__bcnt(A)==1u, A) },
        { A!=0,                                               __iff(__bcnt(A)==1u, A) },

        // Constant result.
        //
        { A-A,                                                0 },
        { A+(-A),                                             0 },
        { A&0,                                                0 },
        { A^A,                                                0 },
        { A&(~A),                                             0 },
        { A|-1,                                              -1 },
        { A+(~A),                                            -1 },
        { A^(~A),                                            -1 },
        { A|(~A),                                            -1 },
        { __rotl(A,0),                                        A },
        { __rotr(A,0),                                        A },
        { A>>0,                                               A },
        { A<<0,                                               A },
        //{ A>>B,                                             __iff(B>=__bcnt(A), 0) },     [Removed as partial evaluator will take care of this]
        //{ A<<B,                                             __iff(B>=__bcnt(A), 0) },     [Removed as partial evaluator will take care of this]

        // SUB conversion.
        //
        { A+(-B),                                             A-B },
        { ~((~A)+B),                                          A-B },
        { ~(A-B),                                             (~A)+B },
        { (~A+U),                                             (U-1)-A },

        // NEG conversion.
        //
        { ~(A-1),                                             -A },
        { 0-A,                                                -A },

        // Invert comparison.
        //
        { ~(A>B),                                             A<=B },
        { ~(A>=B),                                            A<B },
        { ~(A==B),                                            A!=B },
        { ~(A!=B),                                            A==B },
        { ~(A<=B),                                            A>B },
        { ~(A<B),                                             A>=B },
        { ~__ugreat(A,B),                                     __uless_eq(A,B) },
        { ~__ugreat_eq(A,B),                                  __uless(A,B) },
        { ~__uless(A,B),                                      __ugreat_eq(A,B) },
        { ~__uless_eq(A,B),                                   __ugreat(A,B) },

        // NOT conversion.
        //
        { A^-1,                                               ~A },
        { A==0,                                               __iff(__bcnt(A)==1u, A^1) },
        { A!=1,                                               __iff(__bcnt(A)==1u, A^1) },

        // XOR conversion.
        //
        { (A|B)&(~(A&B)),                                     A^B },
        { (A|B)&((~A)|(~B)),                                  A^B },
        { (A&(~B))|((~A)&B),                                  A^B },
        { (~(A|B))|(A&B),                                     ~(A^B) },
        { ((~A)&(~B))|(A&B),                                  ~(A^B) },

        // Simplify AND OR NOT XOR.
        //
        { A&(A|B),                                            A },
        { A|(A&B),                                            A },
        { A^(A&B),                                            A&~B },
        { A^(A|B),                                            B&~A },

        // Simplify rotation count.
        //
        { __rotl(A,U),                                        __iff(U>=__bcnt(A), __rotl(A,!(U%__bcnt(A)))) },
        { __rotr(A,U),                                        __iff(U>=__bcnt(A), __rotr(A,!(U%__bcnt(A)))) },

        // Convert SHL|SHR and OR combinations to rotate.
        //
        { (A>>B)|(A<<C),                                      __iff(C==(__bcnt(A)-B), __rotr(A,B)) },
        { (A<<B)|(A>>C),                                      __iff(C==(__bcnt(A)-B), __rotl(A,B)) },

        // Drop unnecessary casts.
        //
        { __ucast(A,B),                                       __iff(__bcnt(A)==B, A) },
        { __cast(A,B),                                        __iff(__bcnt(A)==B, A) },

        // Simplify SHL|SHR and ROTL|ROTR.
        //
        //{ __ucast(A,B)>>U,                                    __iff((__mask(A)>>U)==0, 0) },              [Removed as partial evaluator will take care of this]
        //{ __cast(A,B)>>U,                                     __iff((__mask(A)>>U)==0, -1>>U) },          [Removed as partial evaluator will take care of this]
        //{ __ucast(A,B)<<U,                                    __iff((__mask(A)<<U)==0, 0) },              [Removed as partial evaluator will take care of this]
        { __cast(A,B)<<U,                                     __iff(U>((B*8)-__bcnt(A)), __ucast(A,B)<<U) },

        // Simplify AND/OR/NOT combinations.
        //
        { (~A)&(~B),                                          ~(A|B) },
        { (~A)|(~B),                                          ~(A&B) },
        { ~(U&A),                                             !(~U)|s(~A) },
        { ~(U|A),                                             !(~U)&s(~A) },
        { (A&B)|(A&C),                                        A&(B|C) },
        { (A|B)&(A|C),                                        A|(B&C) },

        // -- Special AND OR directives to reduce unknown:
        //
        { U|B,                                                __iff(U==(__mask_knw1(B)), B) },
        { U|B,                                                __iff(((~__mask_knw0(B))&(~U))==0u,  U) },
        { U&B,                                                __iff(U==(__mask_unk(B)|__mask_knw1(B)), B) },
        { U&B,                                                __iff(((~__mask_knw0(B))&U)==0u,  0) },

        // Penetrate shrinked expression with shift left.
        // - This is an exceptional case and has to be addressed due to the fact
        //   that when (A>>C) is shrinked, the cast cannot propagate down to A
        //   and unless we add this rule to try simplifying after penetrating it
        //   it cannot escape the cast and simplify with the newly added shift.
        //
        { __ucast(A,B)<<U,                                    __iff(__bcnt(A)>B,    __ucast(!(A<<U), B) ) },

        // Merge ucast combinations.
        //
        { __ucast(A,U)|__ucast(B,U),                          __iff(__bcnt(A)>=__bcnt(B), __ucast(!(A|B),U)) },
        { __ucast(A,U)&__ucast(B,U),                          __iff(__bcnt(A)>=__bcnt(B), __ucast(!(A&B),U)) },
        { __ucast(A,U)^__ucast(B,U),                          __iff(__bcnt(A)>=__bcnt(B), __ucast(!(A^B),U)) },

        // Simplify manual sign extension.
        //
        { __ucast(A, B)|(__ucast((0x1+~(A>>U)), B)<<C),       __iff((B>__bcnt(A))&(U==(__bcnt(A)-1))&(C==__bcnt(A)), __cast(A,B)) },
        { __ucast(A, B)|((~(__ucast(A,B)>>U)+0x1)<<C),        __iff((B>__bcnt(A))&(U==(__bcnt(A)-1))&(C==__bcnt(A)), __cast(A,B)) },
    };

    // Describes the way operands of two operators join each other.
    // - Has no obligation to produce simple output, should be checked.
    //
    static const std::pair<instance::reference, instance::reference> join_descriptors[] =
    {
        // TODO: Arithmetic operators, */% etc.
        // TODO: Should we add ADD and SUB to bitwise despite the partial evaluator?
        //

        // -- Special AND OR directives to reduce unknown:
        //
        { A|B,                                                __iff((__mask_knw1(A)&__mask_unk(B))!=0u, A|!(B&!(~__mask_knw1(A))))},
        { A&B,                                                __iff((__mask_knw0(A)&~__mask_knw0(B))!=0u, A&!(B&!(~__mask_knw0(A))))},

        // -- Special OR substitute to ADD:
        //
        { A+B,                                                __iff( ((__mask_knw1(A)|__mask_unk(A))&(__mask_knw1(B)|__mask_unk(B)))==0u, A|B)},

        // ADD:
        //
        { A+(B+C),                                            !(A+B)+C },
        { A+(B-C),                                            !(A+B)-C },
        { A+(B-C),                                            !(A-C)+B },

        // SUB:
        //
        { A-(B+C),                                            !(A-B)-C },
        { A-(B-C),                                            !(A+C)-B },
        { A-(B-C),                                            !(A-B)+C },
        { (B+C)-A,                                            !(B-A)+C },
        { (B-C)-A,                                            !B-(A+C) },
        { (B-C)-A,                                            !(B-A)-C },

        // OR:
        //
        { A|(B|C),                                            !(A|B)|!(A|C) },
        { A|(B|C),                                            !(A|B)|__or(!(A|C), C) },
        { A|(B&C),                                            !(A|B)&!(A|C) },
        { A|(B&C),                                            A|(!(A|B)&C) },
        { A|(B^C),                                            A|s(!(B&s(~A))^s(C&(~A))) },
        { A|(B<<U),                                           !(!(A>>U)|B)<<U|s(A&((1<<U)-1)) },
        { A|(B>>U),                                           !(!(A<<U)|B)>>U|s(A&(~((-1<<U)>>U))) },
        { A|(__rotl(B,C)),                                    __rotl(!(B|s(__rotr(A,C))), C) },
        { A|(__rotr(B,C)),                                    __rotr(!(B|s(__rotl(A,C))), C) },
        { A|~B,                                               ~!(B&s(~A)) },

        // AND:
        //
        { A&(B|C),                                            !(A&B)|!(A&C) },
        { A&(B|C),                                            A&s(!(A&B)|C) },
        { A&(B&C),                                            !(A&B)&!(A&C) },
        { A&(B&C),                                            !(A&B)&__or(!(A&C),C) },
        { A&(B^C),                                            !(A&B)^!(A&C) },
        { A&(B^C),                                            A&s(!(A&B)^C) },
        { A&(B<<U),                                           !(!(A>>U)&B)<<U },
        { A&(B>>U),                                           !(!(A<<U)&B)>>U },
        { A&(__rotl(B,C)),                                    __rotl(!(B&s(__rotr(A,C))), C) },
        { A&(__rotr(B,C)),                                    __rotr(!(B&s(__rotl(A,C))), C) },
        { A&~B,                                               ~!(B|s(~A)) },

        // XOR:
        //
        { A^(B&C),                                            s(A|(B&C))&s(~(B&!(A&C))) },
        { A^(B|C),                                            s(B|!(A|C))&s(~(A&(B|C))) },
        { A^(B^C),                                            B^!(A^C) },
        { A^(B<<U),                                           !(!(A>>U)^B)<<U|s(A&((1<<U)-1)) },
        { A^(B>>U),                                           !(!(A<<U)^B)>>U|s(A&(~((-1<<U)>>U))) },
        { A^(__rotl(B,C)),                                    __rotl(!(B^s(__rotr(A,C))), C) },
        { A^(__rotr(B,C)),                                    __rotr(!(B^s(__rotl(A,C))), C) },
        { A^~B,                                               !(~A)^B },

        // SHL:
        //
        { (A|B)<<C,                                           !(A<<C)|s(B<<C) },
        { (A&B)<<C,                                           !(A<<C)&s(B<<C) },
        { (A^B)<<C,                                           !(A<<C)^s(B<<C) },
        { (A<<B)<<C,                                          A<<!(B+C) },
        { (A>>B)<<C,                                          __iff(B>=C, !((-1>>B)<<C)&(A>>!(B-C))) },
        { (A>>C)<<B,                                          __iff(B>=C, !((-1>>C)<<B)&(A<<!(B-C))) },
        // Missing: __rotl, __rotr
        { (~A)<<U,                                            (~(A<<U))&(-1<<U) },

        // SHR:
        //
        { (A|B)>>C,                                           !(A>>C)|s(B>>C) },
        { (A&B)>>C,                                           !(A>>C)&s(B>>C) },
        { (A^B)>>C,                                           !(A>>C)^s(B>>C) },
        { (A<<C)>>B,                                          __iff(B>=C, !((-1<<C)>>B)&(A>>!(B-C))) },
        { (A<<B)>>C,                                          __iff(B>=C, !((-1<<B)>>C)&(A<<!(B-C))) },
        { (A>>B)>>C,                                          A>>!(B+C) },
        // Missing: __rotl, __rotr
        { (~A)>>U,                                            (~(A>>U))&(-1>>U) },

        // ROL:
        //
        { __rotl(A|B,C),                                      __rotl(A,C)|__rotl(B,C) },
        { __rotl(A&B,C),                                      __rotl(A,C)&__rotl(B,C) },
        { __rotl(A^B,C),                                      __rotl(A,C)^__rotl(B,C) },
        // Missing: shl, shr
        { __rotl(__rotl(A,B),C),                              __rotl(A,!(B+C)) },
        { __rotl(__rotr(A,B),C),                              __iff(B>=C, __rotr(A,!(B-C))) },
        { __rotl(__rotr(A,C),B),                              __iff(B>=C, __rotl(A,!(B-C))) },
        { __rotl(~A,C),                                       ~__rotl(A,C) },

        // ROR:
        //
        { __rotr(A|B,C),                                      __rotr(A,C)|__rotr(B,C) },
        { __rotr(A&B,C),                                      __rotr(A,C)&__rotr(B,C) },
        { __rotr(A^B,C),                                      __rotr(A,C)^__rotr(B,C) },
        // Missing: shl, shr
        { __rotr(__rotl(A,B),C),                              __iff(B>=C, __rotl(A,(B-C))) },
        { __rotr(__rotl(A,C),B),                              __iff(B>=C, __rotr(A,(B-C))) },
        { __rotr(__rotr(A,B),C),                              __rotr(A,(B+C)) },
        { __rotr(~A,C),                                       ~__rotr(A,C) },

        // NOT:
        //
        { ~(A|B),                                             !(~A)&s(~B)  },
        { ~(A&B),                                             !(~A)|s(~B)  },
        { ~(A^B),  !(~A)^B  },
        // Missing: shl, shr
        { ~__rotl(A,C),                                       __rotl(!~A,C) },
        { ~__rotr(A,C),                                       __rotr(!~A,C) },


        // Manually added comparison simplifiers:
        //
        { (A<<B)==C,                                          s((A<<B)>>B)==s(C>>B) },
        { (A>>B)==C,                                          s((A>>B)<<B)==s(C<<B) },
        { ((A<<B)|C)==0,                                      __iff(A==((A<<B)>>B), (A|C)==0u ) },
        { (A|B)==0,                                           s(A==0) & s(B==0) },
        { __ucast(A,B)==C,                                    __iff(__bcnt(A)<=__bcnt(C), __iff(C==__ucast(C,__bcnt(A)), A==s(__ucast(C,__bcnt(A))))) },
        { __ucast(A,B)==C,                                    __iff(__bcnt(A)<=__bcnt(C), __iff(C!=__ucast(C,__bcnt(A)), 0)) },
    };

    // Grouping of simple representations into more complex directives.
    //
    static const std::pair<instance::reference, instance::reference> pack_descriptors[] =
    {
        { __ucast(A>>B, 0x1),                                 __bt(A, B) },
        { (A>>B)&1,                                           __ucast(__bt(A,B),__bcnt(A)) },
        { (A&B)>>C,                                           __iff((B>>C)==1u, __ucast(__bt(A,C),__bcnt(A))) },
        { __if(A<=B,A)|__if(A>B,B),                           __min(A,B) },
        { __if(A<=B,A)+__if(A>B,B),                           __min(A,B) },
        { __if(A>=B,A)|__if(A<B,B),                           __max(A,B) },
        { __if(A>=B,A)+__if(A<B,B),                           __max(A,B) },
        { __if(__uless_eq(A,B),A)|__if(__ugreat(A,B),B),      __umin(A,B) },
        { __if(__uless_eq(A,B),A)+__if(__ugreat(A,B),B),      __umin(A,B) },
        { __if(__ugreat_eq(A,B),A)|__if(__uless(A,B),B),      __umax(A,B) },
        { __if(__ugreat_eq(A,B),A)+__if(__uless(A,B),B),      __umax(A,B) },
        { (~(A+(-1)))&B,                                      __iff((__mask_unk(A)|__mask_knw1(A))==1u, __if(s(__ucast(A,1)),B)) },
        { (~(A-1))&B,                                         __iff((__mask_unk(A)|__mask_knw1(A))==1u, __if(s(__ucast(A,1)),B)) },
        { ((A+(-1)))&B,                                       __iff((__mask_unk(A)|__mask_knw1(A))==1u, __if(s(__ucast(~A,1)),B)) },
        { ((A-1))&B,                                          __iff((__mask_unk(A)|__mask_knw1(A))==1u, __if(s(__ucast(~A,1)),B)) },
    };

    // Conversion from more complex directives into simple representations.
    //
    static const std::pair<instance::reference, instance::reference> unpack_descriptors[] =
    {
        { __bt(A,B),                                          __ucast((A&(1<<B))>>B,1) },
        { __min(A,B),                                         __if(A<=B,A)|__if(A>B,B) },
        { __max(A,B),                                         __if(A>=B,A)|__if(A<B,B) },
        { __umin(A,B),                                        __if(__uless_eq(A,B),A)|__if(__ugreat(A,B),B) },
        { __umax(A,B),                                        __if(__ugreat_eq(A,B),A)|__if(__uless(A,B),B) },
        { __if(~A,B),                                         (((__ucast(A,__bcnt(B))&1)-1))&B },
        { __if(A,B),                                          (~((__ucast(A,__bcnt(B))&1)-1))&B },
    };
};