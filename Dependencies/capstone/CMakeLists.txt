# Set CMake options for dependencies
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "")
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "")
set(CAPSTONE_BUILD_STATIC_RUNTIME OFF CACHE BOOL "")
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "")
set(CAPSTONE_INSTALL OFF CACHE BOOL "")
set(BUILD_LIBS_ONLY ON CACHE BOOL "")

# Fetch the repository and execute capstone's CMakeLists.txt
message(STATUS "Fetching capstone (this might take a while)...")
FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/aquynh/capstone
    GIT_TAG        d71c95b09b1fa478c0ab9294b07fd6f2efaa1b31
    GIT_SHALLOW    false
)
FetchContent_MakeAvailable(capstone)

# These CMake projects erroneously do not specify INTERFACE include directory, so
# we need to add it ourselves.
# This is a slight hack, FetchContent_GetProperties is supposed to do this for us, but it doesnt.
#
# TODO: Maybe contribute a fix to these upstream projects?
#
get_target_property(capstone_SOURCE_DIR capstone-static SOURCE_DIR)
set_property(TARGET capstone-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${capstone_SOURCE_DIR}/include)

# Downgrade C++ standard on these targets since they depend on some removed/deprecated features
set_property(TARGET capstone-static PROPERTY CXX_STANDARD 11)
set_property(TARGET capstone-static PROPERTY CXX_STANDARD_REQUIRED ON)