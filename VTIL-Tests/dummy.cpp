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