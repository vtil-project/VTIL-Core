project(VTIL-Common)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS *.cpp *.hpp)
file(GLOB_RECURSE INCLUDES CONFIGURE_DEPENDS includes/*)

add_library(${PROJECT_NAME} STATIC
    ${SOURCES}
    ${INCLUDES}
)

source_group(TREE ${PROJECT_SOURCE_DIR} FILES ${SOURCES} ${INCLUDES})

target_include_directories(${PROJECT_NAME} PUBLIC includes)

# Common needs Capstone & Keystone
target_link_libraries(${PROJECT_NAME} capstone-static keystone)

# Put all VTIL-specific compiler flags here
# Linking (indirectly) to VTIL-Common will automatically propagate these flags
# https://www.youtube.com/watch?v=bsXLMQ6WgIk

# https://cmake.org/cmake/help/v3.14/manual/cmake-compile-features.7.html#requiring-language-standards
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

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
    # -fpermissive MSVC equivalent
    target_compile_options(${PROJECT_NAME} PUBLIC /permissive-)
endif()