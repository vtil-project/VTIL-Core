# VTIL-SymEx target
#

set(symex_SOURCES directives/directive.cpp
    directives/transformer.cpp
    expressions/expression.cpp
    expressions/unique_identifier.cpp
    simplifier/simplifier.cpp
)

add_library(symex STATIC ${symex_SOURCES})
target_include_directories(symex PUBLIC "./includes")
target_link_libraries(symex common)
set_property(TARGET symex PROPERTY CXX_STANDARD 20)
set_property(TARGET symex PROPERTY CXX_STANDARD_REQUIRED ON)

# For portability on non-MSVC compilers, disable volatile warnings and allow type narrowing on Clang.
# Fix the bugs on MSVC with -fpermissive.
#
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    string(APPEND CMAKE_CXX_FLAGS "-Wno-volatile")
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    string(APPEND CMAKE_CXX_FLAGS " -Wno-c++11-narrowing -Wno-deprecated-volatile")
elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    string(APPEND CMAKE_CXX_FLAGS " /permissive-")
endif()