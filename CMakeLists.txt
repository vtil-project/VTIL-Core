# Require at least CMake version 3.15 or later for FetchContent
cmake_minimum_required(VERSION 3.14.5)

# Define the VTIL project
project(VTIL)

option(VTIL_BUILD_TESTS "Build tests" OFF)

# Append the CMake module search path so we can use our own modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

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
# Use this target in projects that use VTIL: https://github.com/vtil-project/VTIL-Samples
#
add_subdirectory(VTIL)

# Tests
if(VTIL_BUILD_TESTS)
    add_subdirectory(VTIL-Tests)
endif()
