# Require at least CMake version 3.15 or later for FetchContent
cmake_minimum_required(VERSION 3.14.5)

# Define the VTIL project
project(VTIL-Core)

option(VTIL_BUILD_TESTS "Build tests" OFF)

# Enable solution folder support
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Load the dependencies
set(CMAKE_FOLDER "VTIL-Core/Dependencies")
add_subdirectory(Dependencies)

# Include subprojects
# The dependency chain order is  Common > Architecture + SymEx > Optimizer, so include in that order
#
set(CMAKE_FOLDER "VTIL-Core")
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
