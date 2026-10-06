#include "doctest.h"
#include <vtil/math>

DOCTEST_TEST_CASE("mulh64 signed high multiplication")
{
    CHECK(vtil::math::mulh64(-0x100000000ll, 0x100000000ll) == -1);
    CHECK(vtil::math::mulh64(0x100000000ll, -0x100000000ll) == -1);
}
