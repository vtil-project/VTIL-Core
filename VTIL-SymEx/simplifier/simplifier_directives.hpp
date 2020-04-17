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
#include "..\directives\directive.hpp"
#include <vtil/utility>

namespace vtil::symbolic
{
    // Symbolic variables used in rule creation:
    //
    static const directive A = { "\xCE\xB1" };
    static const directive B = { "\xCE\xB2" };
    static const directive C = { "\xCE\xBB" };

    // Special variables:
    //
    static const directive N = { "\xCE\xA9" }; // Equal to the bit-count of expression.
    static const directive V = { "\xCF\x80" }; // Only accepts variables.
    static const directive U = { "\xCE\xBC" }; // Only accepts constants.
    static const directive X = { "\xCE\xA8" }; // Only accepts constants or variables.

    static const directive& special_bitcnt = N;
    static const directive& special_var = V;
    static const directive& special_const = U;
    static const directive& special_var_const = X;

    static priority_list<std::pair<directive, directive>> basic_simplifiers =
    {
        // Double inverse.
        //
        { -(-A),				    A },
        { ~(~A),				    A },
        { -(~A),				    A+1 },
        { ~(-A),				    A-1 },

        // Identity constants.
        //
        { A+0,					    A },
        { A-0,					    A },
        { A|A,					    A },
        { A|0,					    A },
        { A&A,					    A },
        { A^0,					    A },
        { A&-1,					    A },

        // Constant result.
        //
        { A-A,					    0ll },
        { A+(-A),				    0ll },
        { A&0,					    0ll },
        { A^A,					    0ll },
        { A&(~A),				    0ll },
        { A|-1,					    -1 },
        { A^(~A),				    -1 },
        { A|(~A),				    -1 },
        { __rotl(A,0),			    A },
        { __rotr(A,0),			    A },
        { A>>0,					    A },
        { A<<0,					    A },

        // SUB conversion.
        //
        { ~((~A)+B),			    A-B },
        { ~(A-B),				    (~A)+B },

        // NEG conversion.
        //
        { ~(A-1),				    -A },
        { 0-A,					    -A },

        // Simplify AND OR NOT.
        //
        { A&(A|B),				    A },
        { A|(A&B),				    A },
        //{ A&(B|C),				    __iff((A&B)==B, __iff((A&C)==C, B|C)) },
        //{ A&(B^C),				    __iff((A&B)==B, __iff((A&C)==C, B^C)) },
        //{ A&(B|C),				    __iff((A&B)==0, __iff((A&C)==0, 0ll)) },
        //{ A&(B^C),				    __iff((A&B)==0, __iff((A&C)==0, 0ll)) },
        //{ A|(B|C),				    __iff((A|__unpack(B,C))==__unpack(B,C), __unpack(B,C)|__unpack(C,B)) },
        
        // XOR|NAND|NOR -> NOT conversion.
        //
        { A^-1,					    ~A },
        
        // Prefer SUB over NEG.
        //
        { A+(-B),				    A-B },

        // Convert into XOR.
        //
        { (A|B)&(~(A&B)),		    A^B },
        { (A&(~B))|((~A)&B),	    A^B },
        { (~(A|B))|(A&B),		    ~(A^B) },

        // Simplify SHL|SHR and ROTL|ROTR.
        //
        { A>>B,					    __iff(B>=N, 0ll) },
        { A<<B,					    __iff(B>=N, 0ll) },
        { __zx(A,B)>>C,			    __iff((__mask(A)>>C)==0, 0ll) },
        { __sx(A,B)>>C,			    __iff((__mask(A)>>C)==0, -1>>C) },
        { __rotl(__rotl(A,B),C),    __rotl(A,!(B+C)) },
        { __rotr(__rotr(A,B),C),    __rotr(A,!(B+C)) },

        // Convert SHL|SHR and OR combinations to rotate.
        //
        { (A>>B)|(A<<C),            __iff(C==(64-B), __rotr(A,B)) },
        { (A<<B)|(A>>C),            __iff(C==(64-B), __rotl(A,B)) },

        // Merge two SHL|SHR or ROTL|ROTR instances.
        //
        { (A>>B)>>C,			    A>>!(B+C) },
        { (A<<B)<<C,			    A<<!(B+C) },
        { __rotl(__rotr(A,B),C),    __iff(B>=C, __rotr(A,!(B-C))) },
        { __rotl(__rotr(A,C),B),    __iff(B>=C, __rotl(A,!(B-C))) },
        { __rotr(__rotl(A,B),C),    __iff(B>=C, __rotl(A,!(B-C))) },
        { __rotr(__rotl(A,C),B),    __iff(B>=C, __rotr(A,!(B-C))) },
        { (A>>B)<<C,			    __iff(B>=C, !((-1>>B)<<C)&(A>>!(B-C))) },
        { (A>>C)<<B,			    __iff(B>=C, !((-1>>C)<<B)&(A<<!(B-C))) },
        { (A<<B)>>C,			    __iff(B>=C, !((-1<<B)>>C)&(A<<!(B-C))) },
        { (A<<C)>>B,			    __iff(B>=C, !((-1<<C)>>B)&(A>>!(B-C))) },

        // Simplify
        //

        // ????
        //
        //{ ~A|~B,                    ~(A&B) },
        //{ ~A&~B,                    ~(A|B) },
        //{ (A>>C)|(B>>C),		    (A|B)>>C },
        //{ (A>>C)&(B>>C),		    (A&B)>>C },
        //{ (A<<C)|(B<<C),		    (A|B)<<C },
        //{ (A<<C)&(B<<C),		    (A&B)<<C },

        // Distribute ADD
        //
        { A+(B+C),				    !(A+__unpack(B,C))+__unpack(C,B) },
        { A+(B-C),				    !(A+B)-C },
        { A+(B-C),				    !(A-C)+B },
        
        // Distribute SUB
        //
        { A-(B-C),				    !(A-B)+C },
        { A-(B-C),				    !(A+C)-B },
        { A-(B+C),				    !(A-__unpack(B,C))-__unpack(C,B) },
        { (B-C)-A,				    !(B-A)-C },
        { (B-C)-A,				    B-!(A+C) },
        { (B+C)-A,				    !(__unpack(B,C)-A)+__unpack(C,B) },


        // Dist. shift
            
        //{ A&(B&C),				    !(A&__unpack(B,C))&__unpack(C,B) },
        //{ A|(B|C),				    !(A|__unpack(B,C))|__unpack(C,B) },


        { (A|B)>>C,				    (A>>C)|(B>>C) },
        { (A|B)<<C,				    (A<<C)|(B<<C) },
        { (A&B)>>C,				    (A>>C)&(B>>C) },
        { (A&B)<<C,				    (A<<C)&(B<<C) },
        { (A^B)>>C,				    (A>>C)^(B>>C) },
        { (A^B)<<C,				    (A<<C)^(B<<C) },
        { (~A)>>U,				    (~(A>>U))&(-1>>U) },
        { (~A)<<U,				    (~(A<<U))&(-1<<U) },
            
        { ~(A|B),                   (~A)&(~B) },
        { ~(A&B),                   (~A)|(~B) },
        { ~(A^B),                   (~A)^B },


        //{ X&(B<<U),				    !(!(X>>U)&B)<<U },
        //{ X&(B>>U),				    !(!(X<<U)&B)>>U },
        //{ X|(B<<U),				    (X&((1<<U)-1))|!(!(X>>U)|B)<<U },
        //{ X|(B>>U),				    (X&~(-1<<U))|!(!(X<<U)|B)>>U },
        //{ X^(B<<U),				    (X&((1<<U)-1))|!(!(X>>U)^B)<<U },
        //{ X^(B>>U),				    (X&~(-1<<U))|!(!(X<<U)^B)>>U },
        
        // -> __unpack(C, B)NF
        //{ A&~(B|C),				    ~(!((~A)|__unpack(B, C))|__unpack(C, B)) },
        //{ A&~(B&C),				    !(A&~__unpack(B, C))|(A&~__unpack(C, B)) },
        //{ A|~(B|C),				    ~(!(__unpack(B, C)&~A)|(__unpack(C, B)&~A)) },
        //{ A|~(B&C),				    ~(!((~A)&__unpack(B, C))&__unpack(C, B)) },
    };

    static priority_list<std::pair<directive, directive>> complex_directives =
    {
        // Distribute ADD
        //
        { A+(B+C),				    !(A+__unpack(B,C))+__unpack(C,B) },
        { A+(B-C),				    !(A+B)-C },
        { A+(B-C),				    !(A-C)+B },
        
        // Distribute SUB
        //
        { A-(B-C),				    !(A-B)+C },
        { A-(B-C),				    !(A+C)-B },
        { A-(B+C),				    !(A-__unpack(B,C))-__unpack(C,B) },
        { (B-C)-A,				    !(B-A)-C },
        { (B-C)-A,				    B-!(A+C) },
        { (B+C)-A,				    !(__unpack(B,C)-A)+__unpack(C,B) },

        // Mask with variable mask.
        //
        { __zx(A,B)&C,			    __zx(A,B)&!(__mask(A)&C) },

        // Distribute AND
        //
        { A&(B&C),				    !(A&__unpack(B,C))&__unpack(C,B) },
        { A&(B|C),				    !(A&B)|!(A&C) },
        { A&(B|C),				    A&(__or(!(A&B), B)|__or(!(A&C), C)) },
        { A&(B^C),				    !(A&B)^!(A&C) },
        { A&(B^C),				    A&(__or(!(A&B), B)^__or(!(A&C), C)) },
        { A&(B<<U),				    (!(A>>U)&B)<<U },
        { A&(B>>U),				    (!(A<<U)&B)>>U },
        { A&__rotl(B,C),			__rotl(B&!__rotr(A,U),U)},
        { A&__rotr(B,C),			__rotr(B&!__rotl(A,U),U)},
        { A&~B,					    ~!(!(~A)|B) },

        // Distribute OR
        //
        { A|(B|C),				    !(A|__unpack(B,C))|__unpack(C,B) },
        { A|(B&C),				    !(A|B)&!(A|C) },
        { A|(B&C),				    A|(__or(!(!(~A)&B), B)&__or(!(!(~A)&C), C)) },
        { A|(B^C),				    !(A|__unpack(B,C))^__unpack(C,B) },
        { A|(B^C),				    A|(__or(!(!(~A)&B), B)^__or(!(!(~A)&C), C)) },
        { A|(B<<U),				    !(A&((1<<U)-1))|(!(A>>U)|B)<<U },
        { A|(B>>U),				    !(A&~(-1<<U))|(!(A<<U)|B)>>U },
        { A|__rotl(B,U),			__rotl(B|!__rotr(A,U),U)},
        { A|__rotr(B,U),			__rotr(B|!__rotl(A,U),U)},
        { A|~B,					    ~!(!(~A)&B) },

        // Distribute XOR
        //
        { A^(B^C),				    !(A^__unpack(B,C))^__unpack(C,B) },
        { A^(B<<U),				    !(A&((1<<U)-1))|(!(A>>U)^B)<<U },
        { A^(B>>U),				    (A&~(-1<<U))|(!(A<<U)^B)>>U },
        { A^__rotl(B,U),			__rotl(B^!__rotr(A,U),U)},
        { A^__rotr(B,U),			__rotr(B^!__rotl(A,U),U)},
        { A^~B,					    !(~A)^B },

        // Distribute Shift
        //
        { (A|B)>>C,				    !(__unpack(A,B)>>C)|(__unpack(B,A)>>C) },
        { (A|B)<<C,				    !(__unpack(A,B)<<C)|(__unpack(B,A)<<C) },
        { (A&B)>>C,				    !(__unpack(A,B)>>C)&(__unpack(B,A)>>C) },
        { (A&B)<<C,				    !(__unpack(A,B)<<C)&(__unpack(B,A)<<C) },
        { (A^B)>>C,				    !(__unpack(A,B)>>C)^(__unpack(B,A)>>C) },
        { (A^B)<<C,				    !(__unpack(A,B)<<C)^(__unpack(B,A)<<C) },
        { (~A)>>U,				    (~(A>>U))&(-1>>U) },
        { (~A)<<U,				    (~(A<<U))&(-1<<U) },
    
        // Distribute NOT
        //
        { ~(A|B),				    !(~__unpack(A,B))&(~__unpack(B,A)) },
        { ~(A&B),				    !(~__unpack(A,B))|(~__unpack(B,A)) },
        { ~(A^B),				    !(~__unpack(A,B))^(__unpack(B,A)) },

        // Unpack ADD/SUB
        //
        { A+B,					    !(A^B)+!(!(A&B)<<1) },
        { A-B,					    !(A^B)-!(!(~A&B)<<1) },

        // If AND with constant is being applied over ADD we only care about the bits 
        // that are responsible for the creation of the result.
        // TODO: Fix, __maskof def changed
        //
        //{ U&(A+B),				    U&(!(A&__maskof(U))+!(B&__maskof(U))) },
        //{ U&(A-B),				    U&(!(A&__maskof(U))-!(B&__maskof(U))) },

        // Unpack XOR
        //
        { A^B,					    (A|B)&!(~(A&B)) },
    };
};