# Extract project name from folder
get_filename_component(PROJECT_NAME ${CMAKE_CURRENT_LIST_DIR} NAME)
string(REPLACE " " "_" PROJECT_NAME "${PROJECT_NAME}")

# This builds no sources -- it simply aliases a collection of all other targets created by VTIL
#
add_library(${PROJECT_NAME} INTERFACE)

# Add `includes` to VTIL's include directory path
#
target_include_directories(${PROJECT_NAME} INTERFACE includes)

# Mark all other VTIL targets as a dependency of VTIL
#
target_link_libraries(${PROJECT_NAME} INTERFACE VTIL-Architecture VTIL-SymEx VTIL-Common VTIL-Compiler)

# Increase stack size to allow static initialization
#
if(MSVC)
	target_link_options(${PROJECT_NAME} INTERFACE /STACK:67108864)
endif()
