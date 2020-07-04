# Fetches external dependencies by downloading them and including their CMake  
# targets in this project.
#
# Dependencies covered by this:
#  - Capstone (https://github.com/aquynh/capstone)
#  - Keystone (https://github.com/keystone-engine/keystone)

include(FetchContent)

# Define a macro so we can more easily fetch dependencies
macro(FetchDep name git)
    FetchContent_Declare(
        ${name}
        GIT_REPOSITORY    ${git}
        GIT_SHALLOW       true
    )
    FetchContent_MakeAvailable(${name})
endmacro()

# Set CMake options for dependencies
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "")
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "")
set(CAPSTONE_BUILD_STATIC_RUNTIME OFF CACHE BOOL "")
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "")
set(KEYSTONE_BUILD_STATIC_RUNTIME OFF CACHE BOOL "")
set(BUILD_LIBS_ONLY ON CACHE BOOL "")

# Actually fetch dependencies
FetchDep(Capstone "https://github.com/aquynh/capstone.git")
FetchDep(Keystone "https://github.com/mrexodia/keystone.git")

# These CMake projects erroneously do not specify INTERFACE include directory, so
# we need to add it ourselves.
# This is a slight hack, FetchContent_GetProperties is supposed to do this for us, but it doesnt.
#
# TODO: Maybe contribute a fix to these upstream projects?
#
get_target_property(Capstone_SOURCE_DIR capstone-static SOURCE_DIR)
set_property(TARGET capstone-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Capstone_SOURCE_DIR}/include)


get_target_property(Keystone_SOURCE_DIR keystone SOURCE_DIR)
get_target_property(Keystone_INCLUDE_DIRS keystone INCLUDE_DIRECTORIES)
set_property(TARGET keystone PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Keystone_INCLUDE_DIRS} ${Keystone_SOURCE_DIR}/include)

# Downgrade C++ standard on these targets since they depend on some removed/deprecated features
set_property(TARGET capstone-static PROPERTY CXX_STANDARD 11)
set_property(TARGET capstone-static PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET keystone PROPERTY CXX_STANDARD 11)
set_property(TARGET keystone PROPERTY CXX_STANDARD_REQUIRED ON)
