#include "doctest.h"
#include <vtil/vtil>
#include <vtil/arch>

DOCTEST_TEST_CASE("dummy")
{
	auto block = vtil::basic_block::begin(0);
	block->vemits("cpuid");
	vtil::debug::dump(block);
	CHECK(1 == 1);
}

DOCTEST_TEST_CASE("Optimization stack_pinning_pass")
{

    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc reg_eax(vtil::register_physical, X86_REG_EAX, vtil::arch::bit_count, 0);


    vtil::REG_SP.is_valid(true);



    block->mov(reg_eax, 0);
    block->sub(vtil::REG_SP, vtil::arch::size);
    block->push(reg_eax);
    block->pop(reg_eax);
    block->mov(reg_eax, vtil::arch::size);
    block->add(vtil::REG_SP, reg_eax);
    block->vexit(0ull); // marks the end of a basic_block

    vtil::logger::log(":: Before:\n");
    vtil::debug::dump(block->owner);

    vtil::optimizer::stack_pinning_pass{}(block->owner);

    vtil::logger::log(":: After:\n");
    vtil::debug::dump(block->owner);

    CHECK(block->size() == 5);
    CHECK(block->sp_offset == 0);

}



DOCTEST_TEST_CASE("Simplification")
{

    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc eax(vtil::register_physical, X86_REG_EAX, vtil::arch::bit_count);

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

    int i = 0;
    for (auto it = block->begin(); !it.is_end(); i++, it++)
    {
        auto ins = *it;
        if (i == 0)
        {
            // movd     eax          0x1
            CHECK(ins.base == &vtil::ins::mov);
            CHECK(ins.operands.size() == 2);
            CHECK(ins.operands[0].reg().local_id == X86_REG_EAX);
            CHECK(ins.operands[1].imm().ival == 0x1);
        }
        if (i == 1)
        {
            // strd     $sp          -0x4         0x0
            CHECK(ins.base == &vtil::ins::str);
            CHECK(ins.operands.size() == 3);
            CHECK(ins.operands[0].reg().to_string() == "$sp");
            CHECK(ins.operands[1].imm().ival == -(intptr_t)(1 * vtil::arch::size));
            CHECK(ins.operands[2].imm().ival == 0x0);
        }
        if (i == 2)
        {
            // strd     $sp          -0x8         0x1
            CHECK(ins.base == &vtil::ins::str);
            CHECK(ins.operands.size() == 3);
            CHECK(ins.operands[0].reg().to_string() == "$sp");
            CHECK(ins.operands[1].imm().ival == -(intptr_t)(2 * vtil::arch::size));
            CHECK(ins.operands[2].imm().ival == 0x1);
        }
        if (i == 3)
        {
            // vpinrd   eax
            CHECK(ins.base == &vtil::ins::vpinr);
            CHECK(ins.operands.size() == 1);
            CHECK(ins.operands[0].reg().local_id == X86_REG_EAX);
        }
        if (i == 4)
        {
            // vexitq   0x0
            CHECK(ins.base == &vtil::ins::vexit);
            CHECK(ins.operands.size() == 1);
            CHECK(ins.operands[0].imm().ival == 0);
        }

    }

}

