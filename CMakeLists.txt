# Require at least CMake version 3.11 or later
cmake_minimum_required(VERSION 3.11)

# Define the VTIL project
project(VTIL)

# Append the CMake module search path so we can use our own modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

# Suppress unsafe warnings on MSVC
if(MSVC)
    add_definitions(/D_CRT_SECURE_NO_WARNINGS)
endif()

# Resolve external dependencies
# This should automatically pull in Capstone & Keystone as CMake linkable libraries
include(IncludeDeps)

# Include subprojects
# The dependency chain order is  Common > Architecture > SymEx, so include in that order
#
add_subdirectory(VTIL-Common)
add_subdirectory(VTIL-Architecture)
add_subdirectory(VTIL-SymEx)