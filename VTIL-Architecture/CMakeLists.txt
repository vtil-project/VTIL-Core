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

# For portability on non-MSVC compilers, disable volatile warnings
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(architecture PRIVATE "-Wvolatile")
endif()

# Add -fpermissive on MSVC
if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(architecture PRIVATE "/permissive-")
endif()