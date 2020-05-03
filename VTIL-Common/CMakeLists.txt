# VTIL-Common target
#

set(common_SOURCES amd64/assembler.cpp
    amd64/disassembly.cpp
    amd64/register_details.cpp
    io/logger.cpp
    math/operators.cpp
    util/critical_section.cpp
    util/variant.cpp
)

add_library(common STATIC ${common_SOURCES})
target_include_directories(common PUBLIC "./includes")

# Common needs C++20 but some dependencies do not support C++20 due to deprecated
# features, so set the standard for this target only.
set_property(TARGET common PROPERTY CXX_STANDARD 20)
set_property(TARGET common PROPERTY CXX_STANDARD_REQUIRED ON)

# Common needs Capstone & Keystone
target_link_libraries(common capstone-static keystone)

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