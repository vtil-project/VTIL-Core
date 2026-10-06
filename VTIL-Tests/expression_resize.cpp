#include "doctest.h"
#include <vtil/symex>

DOCTEST_TEST_CASE("resize preserves discarded bits after shift_left")
{
    using namespace vtil::symbolic;

    expression::reference x = expression{ unique_identifier{ "x" }, 32 };

    expression::reference shl = x << expression{ 3, 32 };
    expression::reference expected = __ucast( shl, 64 );
    expression::reference resized = shl;

    resized.resize( 64 );

    CHECK( resized.equals( *expected ) );
}

DOCTEST_TEST_CASE("resize preserves discarded bits after rotate_left")
{
    using namespace vtil::symbolic;

    expression::reference x = expression{ unique_identifier{ "x" }, 32 };

    expression::reference rol = __rotl( x, expression{ 3, 32 } );
    expression::reference expected = __ucast( rol, 64 );
    expression::reference resized = rol;

    resized.resize( 64 );

    CHECK( resized.equals( *expected ) );
}

DOCTEST_TEST_CASE("resize preserves discarded bits after rotate_right")
{
    using namespace vtil::symbolic;

    expression::reference x = expression{ unique_identifier{ "x" }, 32 };

    expression::reference ror = __rotr( x, expression{ 3, 32 } );
    expression::reference expected = __ucast( ror, 64 );
    expression::reference resized = ror;

    resized.resize( 64 );

    CHECK( resized.equals( *expected ) );
}
