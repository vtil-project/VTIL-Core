#include "doctest.h"
#include <vtil/vtil>
#include <vtil/arch>
#include <vtil/optimizer-tests>

namespace registers
{
#if _M_X64 || __x86_64__
    constexpr auto ax = X86_REG_RAX;
    constexpr auto bx = X86_REG_RBX;
    constexpr auto cx = X86_REG_RCX;
    constexpr auto dx = X86_REG_RDX;
#elif _M_IX86 || __i386__
    constexpr auto ax = X86_REG_EAX;
    constexpr auto bx = X86_REG_EBX;
    constexpr auto cx = X86_REG_ECX;
    constexpr auto dx = X86_REG_EDX;
#endif
}


DOCTEST_TEST_CASE("dummy")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);
	auto block = vtil::basic_block::begin(0);
	block->vemits("cpuid");
	vtil::debug::dump(block);
	CHECK(1 == 1);
}

DOCTEST_TEST_CASE("Optimization vtil file")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);
    // TODO vtil file
    // auto test1 = vtil::optimizer::validation::test1();
    // auto rtn = test1.generate();
    // CHECK( test1.validate( rtn.get() ) );
}

DOCTEST_TEST_CASE("Optimization stack_pinning_pass")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);
    auto block = vtil::basic_block::begin(0x1337);

    vtil::register_desc reg_ax(vtil::register_physical, registers::ax, vtil::arch::bit_count, 0);

    block->mov(reg_ax, (uintptr_t)0);
    block->sub(vtil::REG_SP, vtil::arch::size);
    block->mov(reg_ax, (uintptr_t)0);
    block->push(reg_ax);
    block->pop(reg_ax);
    block->mov(reg_ax, vtil::arch::size);
    block->add(vtil::REG_SP, reg_ax);

    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::optimizer::stack_pinning_pass{}(block->owner);

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);

    CHECK(block->size() == 6);
    CHECK(block->sp_offset == 0);

}


DOCTEST_TEST_CASE("Optimization istack_ref_substitution_pass")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);
    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc reg_eax(vtil::register_physical, registers::ax, vtil::arch::bit_count, 0);

    // mov eax,esp
    block->mov(reg_eax, vtil::REG_SP);
    // sub eax, 4
    block->sub(reg_eax, vtil::arch::size);
    // mov [eax+0], 1
    block->str(reg_eax, 0, (uintptr_t) 1);
    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::optimizer::istack_ref_substitution_pass{}(block->owner);

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);

    auto ins = (*block) [2];

    // mov [eax-4], 1
    CHECK(ins.base == &vtil::ins::str);
    CHECK(ins.operands.size() == 3);
    CHECK(ins.operands[0].reg().to_string() == "$sp");
    CHECK(ins.operands[1].imm().ival == -(intptr_t)(vtil::arch::size));
    CHECK(ins.operands[2].imm().ival == 0x1);

}


DOCTEST_TEST_CASE("Optimization stack_propagation_pass")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);

    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc reg_eax(vtil::register_physical, registers::ax, vtil::arch::bit_count, 0);


    // mov [esp+0], 0x1234
    block->str(vtil::REG_SP, 0, (uintptr_t)0x1234);
    // mov eax, [esp+0]
    block->ldd(reg_eax, vtil::REG_SP, 0);
    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::optimizer::stack_propagation_pass{}(block->owner);

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);

    auto ins = (*block)[1];

    // mov eax, 0x1234
    CHECK(ins.base == &vtil::ins::mov);
    CHECK(ins.operands.size() == 2);
    CHECK(ins.operands[0].reg().local_id == registers::ax);
    CHECK(ins.operands[1].imm().ival == 0x1234);
}


DOCTEST_TEST_CASE("Optimization dead_code_elimination_pass")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);

    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc reg_eax(vtil::register_physical, registers::ax, vtil::arch::bit_count, 0);


    block->mov(reg_eax, (uintptr_t) 1);
    block->mov(reg_eax, (uintptr_t) 2);
    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::optimizer::dead_code_elimination_pass{}(block->owner);

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);

    CHECK(block->size() == 2);
}


DOCTEST_TEST_CASE("Optimization mov_propagation_pass")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);

    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc reg_eax(vtil::register_physical, registers::ax, vtil::arch::bit_count, 0);
    vtil::register_desc reg_ebx(vtil::register_physical, registers::bx, vtil::arch::bit_count, 0);

    // mov eax, 0x1
    block->mov(reg_eax, (uintptr_t) 1);
    // mov ebx, eax
    block->mov(reg_ebx, reg_eax);
    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::optimizer::mov_propagation_pass{}(block->owner);

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);


    auto ins = (*block)[1];

    //  mov ebx, 0x1
    CHECK(ins.base == &vtil::ins::mov);
    CHECK(ins.operands.size() == 2);
    CHECK(ins.operands[0].reg().local_id == registers::bx);
    CHECK(ins.operands[1].imm().ival == 0x1);
}


DOCTEST_TEST_CASE("Optimization register_renaming_pass")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);

    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc reg_eax(vtil::register_physical, registers::ax, vtil::arch::bit_count, 0);
    vtil::register_desc reg_ebx(vtil::register_physical, registers::bx, vtil::arch::bit_count, 0);

    // mov eax, 1
    block->mov(reg_eax, (uintptr_t) 1);
    // mov ebx, eax
    block->mov(reg_ebx, reg_eax);
    // mov [esp+0], ebx
    block->str(vtil::REG_SP, 0, reg_ebx);
    block->mov(reg_eax, (uintptr_t) 1);
    block->mov(reg_ebx, (uintptr_t) 1);
    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::optimizer::register_renaming_pass{}(block->owner);

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);


    auto ins = (*block)[0];

    //  mov ebx, 1
    CHECK(ins.base == &vtil::ins::mov);
    CHECK(ins.operands.size() == 2);
    CHECK(ins.operands[0].reg().local_id == registers::bx);
    CHECK(ins.operands[1].imm().ival == 0x1);
}


DOCTEST_TEST_CASE("Optimization symbolic_rewrite_pass<true>")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);

    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc reg_eax(vtil::register_physical, registers::ax, vtil::arch::bit_count, 0);
    vtil::register_desc reg_ebx(vtil::register_physical, registers::bx, vtil::arch::bit_count, 0);

    // mov eax, 1
    block->mov(reg_eax, (uintptr_t) 1);
    // mov ebx, eax
    block->mov(reg_ebx, reg_eax);
    // mov[esp+0], ebx
    block->str(vtil::REG_SP, 0, reg_ebx);
    block->mov(reg_eax, (uintptr_t) 1);
    block->mov(reg_ebx, (uintptr_t) 1);
    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::optimizer::symbolic_rewrite_pass<true>{}(block->owner);

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);

    CHECK(block->size() == 4);

    auto ins = (*block)[0];
    // mov eax, 1
    CHECK(ins.base == &vtil::ins::mov);
    CHECK(ins.operands.size() == 2);
    // while ins stream is in disorder
    // CHECK(ins.operands[0].reg().local_id == registers::ax);
    CHECK(ins.operands[1].imm().ival == 0x1);

    ins = (*block)[1];
    // mov ebx, 1
    CHECK(ins.base == &vtil::ins::mov);
    CHECK(ins.operands.size() == 2);
    // CHECK(ins.operands[0].reg().local_id == registers::bx);
    CHECK(ins.operands[1].imm().ival == 0x1);

    ins = (*block)[2];
    // mov[esp+0], 1
    CHECK(ins.base == &vtil::ins::str);
    CHECK(ins.operands.size() == 3);
    CHECK(ins.operands[0].reg().to_string() == "$sp");
    CHECK(ins.operands[2].imm().ival == 0x1);
}


DOCTEST_TEST_CASE("Optimization dead_code_elimination_pass")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);

    // simple single block
    {
        auto block = vtil::basic_block::begin( 0x1337 );
        vtil::register_desc reg_eax( vtil::register_physical, registers::ax, vtil::arch::bit_count, 0 );
        vtil::register_desc reg_ebx( vtil::register_physical, registers::bx, vtil::arch::bit_count, 0 );

        // push eax
        block->push( reg_eax );
        // push ebx
        block->push( reg_ebx );

        // sp -= 0x10
        block->shift_sp( 0x10 );
        // mov eax, 0
        block->mov( reg_eax, (uintptr_t)0 );
        // vexit 0
        block->vexit( 0ull ); // marks the end of a basic_block

        vtil::logger::log( ":: Before:\n" );
        vtil::debug::dump( block->owner );

        vtil::optimizer::dead_code_elimination_pass{}( block->owner );

        vtil::logger::log( ":: After:\n" );
        vtil::debug::dump( block->owner );

        // mov eax, 0
        // vexit 0
        CHECK( block->size() == 2 );
    }
    
    // with jmp
    {
        auto block1 = vtil::basic_block::begin( 0x1337 );
        
        vtil::register_desc reg_eax( vtil::register_physical, registers::ax, vtil::arch::bit_count, 0 );
        vtil::register_desc reg_ebx( vtil::register_physical, registers::bx, vtil::arch::bit_count, 0 );

        {
            // push eax
            block1->push( reg_eax );
            // push ebx
            block1->push( reg_ebx );
            // jmp 0x2000
            block1->jmp( (uintptr_t) 0x2000 );
        }

        auto block2 = block1->fork( 0x2000 );
        {
            // sp -= 0x10
            block2->shift_sp( 0x10 );
            // mov eax, 0
            block2->mov( reg_eax, (uintptr_t)0 );
            // vexit 0
            block2->vexit( 0ull ); // marks the end
        }

        vtil::logger::log( ":: Before:\n" );
        vtil::debug::dump( block1->owner );

        vtil::optimizer::dead_code_elimination_pass{}( block1->owner );

        vtil::logger::log( ":: After:\n" );
        vtil::debug::dump( block1->owner );

        // jmp 0x2000
        CHECK( block1->size() == 1 );
    }

    // with te jmp
    {
        auto block1 = vtil::basic_block::begin( 0x1337 );

        vtil::register_desc reg_eax( vtil::register_physical, registers::ax, vtil::arch::bit_count, 0 );
        vtil::register_desc reg_ebx( vtil::register_physical, registers::bx, vtil::arch::bit_count, 0 );
        vtil::register_desc reg_ecx( vtil::register_physical, registers::cx, vtil::arch::bit_count, 0 );

        {
            // push eax
            block1->push( reg_eax );
            // push ebx
            block1->push( reg_ebx );
            // ecx = ecx == 0xAABB
            block1->te(  reg_ecx, reg_ecx, (uintptr_t)0xAABB );
            // js ecx ? 0x2000, 0x3000
            block1->js( reg_ecx, (uintptr_t)0x2000, (uintptr_t)0x3000 );
        }

        auto block2 = block1->fork( 0x2000 );
        {
            // sp -= 0x10
            block2->shift_sp( 0x10 );
            // mov eax, 0
            block2->add( reg_eax, (uintptr_t)1 );  // need this to contains [shift_sp]
            // vexit 0
            block2->vexit( 0ull ); // marks the end
        }

        auto block3 = block1->fork( 0x3000 );
        {
            // mov eax, [esp - 8]
            block3->ldd( reg_eax, vtil::REG_SP, -8 );
            // sp -= 0x10
            block3->shift_sp( 0x10 );
            // add eax, 1
            block3->add( reg_eax, (uintptr_t)1 ); // need this to contains [shift_sp]
            // vexit 0
            block3->vexit( 0ull ); // marks the end
        }


        vtil::logger::log( ":: Before:\n" );
        vtil::debug::dump( block1->owner );

        vtil::optimizer::dead_code_elimination_pass{}( block1->owner );

        vtil::logger::log( ":: After:\n" );
        vtil::debug::dump( block1->owner );

        // Cant optimize the block1 (strq) because we use it in block3
        CHECK( block1->size() == 4 );
    }


}

DOCTEST_TEST_CASE("Simplification")
{
    vtil::logger::log("\n\n>> %s \n", __FUNCTION__);
    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc eax(vtil::register_physical, registers::ax, vtil::arch::bit_count);

    block->mov(eax, 0);

    for (int i = 0; i < 2; ++i)
    {
        block->add(eax, 13);
        block->nop();
        block->sub(eax, 12);
        block->nop();
        block->add(eax, 14);
        block->mov(eax, eax);
        block->sub(eax, eax);
        block->bxor(eax, i);
        block->push(eax);
    }

    block->vpinr(eax);  // pin register eax as read so it doesn't get optimized away
    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::logger::log("\n");

    vtil::optimizer::apply_each<
        vtil::optimizer::profile_pass,
        vtil::optimizer::collective_cross_pass
    >{}(block->owner);      // executes all optimization passes

    vtil::logger::log("\n");

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);


    CHECK(block->sp_offset == -(intptr_t)(2 * vtil::arch::size));
    CHECK(block->size() == 5);

    auto ins = (*block)[0];
    // movd     eax          0x1
    CHECK(ins.base == &vtil::ins::mov);
    CHECK(ins.operands.size() == 2);
    CHECK(ins.operands[0].reg().local_id == registers::ax);
    CHECK(ins.operands[1].imm().ival == 0x1);

    ins = (*block)[1];
    // strd     $sp          -0x4         0x0
    CHECK(ins.base == &vtil::ins::str);
    CHECK(ins.operands.size() == 3);
    CHECK(ins.operands[0].reg().to_string() == "$sp");
    CHECK(ins.operands[1].imm().ival == -(intptr_t)(1 * vtil::arch::size));
    CHECK(ins.operands[2].imm().ival == 0x0);

    ins = (*block)[2];
    // strd     $sp          -0x8         0x1
    CHECK(ins.base == &vtil::ins::str);
    CHECK(ins.operands.size() == 3);
    CHECK(ins.operands[0].reg().to_string() == "$sp");
    CHECK(ins.operands[1].imm().ival == -(intptr_t)(2 * vtil::arch::size));
    CHECK(ins.operands[2].imm().ival == 0x1);

    ins = (*block)[3];
    // vpinrd   eax
    CHECK(ins.base == &vtil::ins::vpinr);
    CHECK(ins.operands.size() == 1);
    CHECK(ins.operands[0].reg().local_id == registers::ax);

    ins = (*block)[4];
    // vexitq   0x0
    CHECK(ins.base == &vtil::ins::vexit);
    CHECK(ins.operands.size() == 1);
    CHECK(ins.operands[0].imm().ival == 0);

}

