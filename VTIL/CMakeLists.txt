project(VTIL)

# This builds no sources -- it simply aliases a collection of all other targets created by VTIL
#
add_library(${PROJECT_NAME} INTERFACE)

# Add `includes` to VTIL's include directory path
#
target_include_directories(${PROJECT_NAME} INTERFACE includes)

# Mark all other VTIL targets as a dependency of VTIL
#
target_link_libraries(${PROJECT_NAME} INTERFACE VTIL-Architecture VTIL-SymEx VTIL-Common VTIL-Optimizer) 