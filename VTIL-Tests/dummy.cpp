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

DOCTEST_TEST_CASE("Simplification")
{
#if _M_X64 || __x86_64__
    constexpr auto architecture = vtil::architecture_amd64;
#else
    constexpr auto architecture = vtil::architecture_x86;
#endif

    auto block = vtil::basic_block::begin(0x1337, architecture);
    vtil::register_desc eax(vtil::register_physical, X86_REG_EAX, vtil::arch::bit_count, 0, architecture);

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
}
