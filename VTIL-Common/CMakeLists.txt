project(VTIL-Common)

add_library(${PROJECT_NAME} STATIC
    arch/amd64/amd64_assembler.cpp
    arch/amd64/amd64_assembler.hpp
    arch/amd64/amd64_disassembler.cpp
    arch/amd64/amd64_disassembler.hpp
    arch/amd64/amd64_register_details.cpp
    arch/amd64/amd64_register_details.hpp
    arch/arm64/arm64_assembler.cpp
    arch/arm64/arm64_assembler.hpp
    arch/arm64/arm64_disassembler.cpp
    arch/arm64/arm64_disassembler.hpp
    arch/arm64/arm64_register_details.cpp
    arch/arm64/arm64_register_details.hpp
    arch/register_mapping.hpp
    formats/image_descriptor.hpp
    formats/winpe.cpp
    formats/winpe.hpp
    io/asserts.hpp
    io/formatting.hpp
    io/logger.cpp
    io/logger.hpp
    math/bitwise.hpp
    math/operable.hpp
    math/operators.cpp
    math/operators.hpp
    query/fixed_iterator.hpp
    query/query_descriptor.hpp
    query/range_iterator.hpp
    query/range_iterator_contract.hpp
    query/recursive_view.hpp
    query/view.hpp
    util/concept.hpp
    util/conditional_lock.hpp
    util/constexpr_random.hpp
    util/copy_on_write.hpp
    util/critical_section.cpp
    util/critical_section.hpp
    util/dynamic_size.hpp
    util/fnv128.hpp
    util/fnv64.hpp
    util/hashable.hpp
    util/lt_typeid.hpp
    util/mul128.hpp
    util/multivariate.hpp
    util/numeric_iterator.hpp
    util/optional_reference.hpp
    util/range.hpp
    util/reducable.hpp
    util/reverse_iterator.hpp
    util/sinkhole.hpp
    util/stack_container.hpp
    util/variant.cpp
    util/variant.hpp
    util/zip.hpp
    util/colony.hpp
    util/object_pool.hpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)

# Common needs Capstone & Keystone
target_link_libraries(${PROJECT_NAME} capstone-static keystone)

# Put all VTIL-specific compiler flags here
# Linking (indirectly) to VTIL-Common will automatically propagate these flags
# https://www.youtube.com/watch?v=bsXLMQ6WgIk

# https://crascit.com/2015/03/28/enabling-cxx11-in-cmake/
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

# For portability on non-MSVC compilers, add some compile options
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(${PROJECT_NAME} PUBLIC -Wno-narrowing)
    target_compile_options(${PROJECT_NAME} PUBLIC -Wno-format-security)
    target_compile_options(${PROJECT_NAME} PUBLIC -Wno-unused-value)
    target_compile_options(${PROJECT_NAME} PUBLIC -Wno-uninitialized)
    target_compile_options(${PROJECT_NAME} PUBLIC -Wno-parentheses)
    
    # Clang-only flags
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # Use libc++ if compiling C++
        # NOTE: bad practice, technically you should specify this in your CMake invocation
        target_compile_options(${PROJECT_NAME} PUBLIC -stdlib=libc++)
        target_link_options(${PROJECT_NAME} PUBLIC -stdlib=libc++)
    endif()

    # GCC-only flags
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        target_compile_options(${PROJECT_NAME} PUBLIC -Wvolatile)
        target_compile_options(${PROJECT_NAME} PUBLIC -fpermissive)
        target_compile_options(${PROJECT_NAME} PUBLIC -Wno-attributes)
        target_compile_options(${PROJECT_NAME} PUBLIC -Wno-multichar)
    endif()
endif()

if(MSVC)
    # Supress CRT security warnings
    target_compile_definitions(${PROJECT_NAME} PUBLIC _CRT_SECURE_NO_WARNINGS)
    # -fpermissive MSVC equivalent
    target_compile_options(${PROJECT_NAME} PUBLIC /permissive-)
endif()