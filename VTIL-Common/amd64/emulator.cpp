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
// Furthermore, the following pieces of software have additional copyrights
// licenses, and/or restrictions:
//
// |--------------------------------------------------------------------------|
// | File name               | Link for further information                   |
// |-------------------------|------------------------------------------------|
// | amd64/*                 | https://github.com/aquynh/capstone/            |
// |                         | https://github.com/keystone-engine/keystone/   |
// |--------------------------------------------------------------------------|
//
#include "emulator.hpp"
#include "..\io\asserts.hpp"

// Stack delta if this were to be used as stack.
// - (Thanks ICC)
//
#define sd 0x20
static_assert( sd == vtil::emulator::reserved_stack_size );

namespace vtil
{
    // Invokes routine at the pointer given with the current context and updates the context.
    // - Template argument is a small trick to make it work with ICC, declaring a constexpr within the scope does not work.
    //
    void emulator::invoke( const void* routine_pointer )
    {
        // Set the runtime RIP.
        //
        __rip = routine_pointer;

        _asm
        {
            // Replace the current stack pointer with a this pointer, save the previous stack pointer.
            //
            mov     rax,	rsp
            mov     rsp,	this
            add     rsp,	sd
            mov     [ rsp - sd ] emulator.__rsp, rax

            // Exchange general-purpose registers.
            //
            xchg    rax,	[ rsp - sd ] emulator.v_rax
            xchg    rbx,	[ rsp - sd ] emulator.v_rbx
            xchg    rcx,	[ rsp - sd ] emulator.v_rcx
            xchg    rdx,	[ rsp - sd ] emulator.v_rdx
            xchg    rsi,	[ rsp - sd ] emulator.v_rsi
            xchg    rdi,	[ rsp - sd ] emulator.v_rdi
            xchg    rbp,	[ rsp - sd ] emulator.v_rbp
            xchg    r8,		[ rsp - sd ] emulator.v_r8
            xchg    r9,		[ rsp - sd ] emulator.v_r9
            xchg    r10,	[ rsp - sd ] emulator.v_r10
            xchg    r11,	[ rsp - sd ] emulator.v_r11
            xchg    r12,	[ rsp - sd ] emulator.v_r12
            xchg    r13,	[ rsp - sd ] emulator.v_r13
            xchg    r14,	[ rsp - sd ] emulator.v_r14
            xchg    r15,	[ rsp - sd ] emulator.v_r15

            // Exchange EFLAGS.
            //
            pushfq
            push	[ rsp - sd ] emulator.v_rflags
            popfq
            pop		[ rsp - sd ] emulator.v_rflags

            // Call the function.
            //
            call	[ rsp - sd ] emulator.__rip

            // Exchange EFLAGS.
            //
            pushfq
            push	[ rsp - sd ] emulator.v_rflags
            popfq
            pop		[ rsp - sd ] emulator.v_rflags

            // Exchange general-purpose registers.
            //
            xchg    rax,	[ rsp - sd ] emulator.v_rax
            xchg    rbx,	[ rsp - sd ] emulator.v_rbx
            xchg    rcx,	[ rsp - sd ] emulator.v_rcx
            xchg    rdx,	[ rsp - sd ] emulator.v_rdx
            xchg    rsi,	[ rsp - sd ] emulator.v_rsi
            xchg    rdi,	[ rsp - sd ] emulator.v_rdi
            xchg    rbp,	[ rsp - sd ] emulator.v_rbp
            xchg    r8,		[ rsp - sd ] emulator.v_r8
            xchg    r9,		[ rsp - sd ] emulator.v_r9
            xchg    r10,	[ rsp - sd ] emulator.v_r10
            xchg    r11,	[ rsp - sd ] emulator.v_r11
            xchg    r12,	[ rsp - sd ] emulator.v_r12
            xchg    r13,	[ rsp - sd ] emulator.v_r13
            xchg    r14,	[ rsp - sd ] emulator.v_r14
            xchg    r15,	[ rsp - sd ] emulator.v_r15

            // Restore stack pointer.
            //
            mov	    rsp,	[ rsp - sd ] emulator.__rsp
        }
    }

    // Resolves the offset<0> where the value is saved at for the given register
    // and the number of bytes<1> it takes.
    //
    std::pair<int32_t, uint8_t> emulator::resolve( x86_reg reg ) const
    {
        auto [base_reg, offset, size] = amd64::resolve_mapping( reg );

        const void* base;
        switch ( base_reg )
        {
            case X86_REG_RAX:	base = &v_rax;					break;
            case X86_REG_RBP:	base = &v_rbp;					break;
            case X86_REG_RBX:	base = &v_rbx;					break;
            case X86_REG_RCX:	base = &v_rcx;					break;
            case X86_REG_RDI:	base = &v_rdi;					break;
            case X86_REG_RDX:	base = &v_rdx;					break;
            case X86_REG_RSI:	base = &v_rsi;					break;
            case X86_REG_R8: 	base = &v_r8;					break;
            case X86_REG_R9: 	base = &v_r9;					break;
            case X86_REG_R10:	base = &v_r10;					break;
            case X86_REG_R11:	base = &v_r11;					break;
            case X86_REG_R12:	base = &v_r12;					break;
            case X86_REG_R13:	base = &v_r13;					break;
            case X86_REG_R14:	base = &v_r14;					break;
            case X86_REG_R15:	base = &v_r15;					break;
            default:            unreachable();
        }

        return { ( ( uint8_t* ) base - ( uint8_t* ) this ) + offset, size };
    }

    // Sets the value of a register.
    //
    emulator& emulator::set( x86_reg reg, uint64_t value )
    {
        auto [off, sz] = resolve( reg );
        memcpy( ( uint8_t* ) this + off, &value, sz );
        return *this;
    }

    // Gets the value of a register.
    //
    uint64_t emulator::get( x86_reg reg ) const
    {
        uint64_t value = 0;
        auto [off, sz] = resolve( reg );
        memcpy( &value, ( uint8_t* ) this + off, sz );
        return value;
    }
};
#undef sd