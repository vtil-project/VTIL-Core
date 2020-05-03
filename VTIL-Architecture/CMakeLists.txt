# VTIL-Architecture target
#

set(architecture_SOURCES arch/instruction_desc.cpp
    routine/basic_block.cpp
    routine/instruction.cpp
    routine/routine.cpp
    routine/serialization.cpp
)

add_library(architecture STATIC ${architecture_SOURCES})
target_include_directories(architecture PUBLIC "./includes")
target_link_libraries(architecture common)
set_property(TARGET architecture PROPERTY CXX_STANDARD 20)
set_property(TARGET architecture PROPERTY CXX_STANDARD_REQUIRED ON)

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