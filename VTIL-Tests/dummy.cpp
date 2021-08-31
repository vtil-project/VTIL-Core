#include "doctest.h"
#include <vtil/vtil>
#include <vtil/arch>
#include <vtil/symex>

/*DOCTEST_TEST_CASE("dummy")
{
	auto block = vtil::basic_block::begin(0);
	block->vemits("cpuid");
	vtil::debug::dump(block);
	CHECK(1 == 1);
}

DOCTEST_TEST_CASE("Simplification")
{
    auto block = vtil::basic_block::begin(0x1337);
    vtil::register_desc eax(vtil::register_physical, X86_REG_EAX, 32, 0);

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
    CHECK(1 == 1);
}*/

DOCTEST_TEST_CASE("Expression hash")
{
    // $sp#0x13df89?+0x90 
    using namespace vtil::symbolic;
    using namespace vtil::math;
    using namespace vtil::logger;
    auto block = vtil::basic_block::begin(0x13df89);
    block->nop();
    auto var = variable(block->begin(), vtil::REG_SP);
    log("var hash: %s\n", var.hash());

    auto v = var.to_expression();
    log("v hash: %s\n", v.hash());
    //expression(unique_identifier())
    auto c = expression(0x90);
    log("c hash: %s\n", c.hash());
    auto kurwa = expression::make(v, operator_id::add, c);
    log("%s (Hash: %s)\n", kurwa.to_string(), kurwa.hash());
    kurwa.update(false);
    log("%s (Hash: %s)\n", kurwa.to_string(), kurwa.hash());
}