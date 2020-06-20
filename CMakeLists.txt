# Require at least CMake version 3.15 or later for FetchContent
cmake_minimum_required(VERSION 3.14.5)

# Define the VTIL project
project(VTIL)

option(VTIL_BUILD_TESTS "Build tests" OFF)

# Append the CMake module search path so we can use our own modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

# For portability on non-MSVC compilers, add some compile options
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-Wno-narrowing)
	add_compile_options(-Wno-format-security)
	add_compile_options(-Wno-unused-value)
	add_compile_options(-Wno-uninitialized)
	add_compile_options(-Wno-parentheses)
	
    # Clang-only flags
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # Use libc++ if compiling C++
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -stdlib=libc++")
    endif()

    # GCC-only flags
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        add_compile_options(-Wvolatile)
        add_compile_options(-fpermissive)
        add_compile_options(-Wno-attributes)
        add_compile_options(-Wno-multichar)
    endif()
endif()



if(MSVC)
    # Supress CRT security warnings
    add_definitions(/D_CRT_SECURE_NO_WARNINGS)
    # -fpermissive MSVC equivalent
    add_compile_options(/permissive-)
endif()

# Set default C++ standard to C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

# Resolve external dependencies
# This should automatically pull in Capstone & Keystone as CMake linkable libraries
include(IncludeDeps)

# Include subprojects
# The dependency chain order is  Common > Architecture + SymEx > Optimizer, so include in that order
#
add_subdirectory(VTIL-Common)
add_subdirectory(VTIL-SymEx)
add_subdirectory(VTIL-Architecture)
add_subdirectory(VTIL-Compiler)

# After all other targets are defined, include the VTIL interface target
#
add_subdirectory(VTIL)

# Tests
if(VTIL_BUILD_TESTS)
    add_subdirectory(VTIL-Tests)
endif()