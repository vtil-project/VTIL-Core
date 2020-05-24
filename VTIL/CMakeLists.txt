# VTIL target
# This builds no sources -- it simply aliases a collection of all other targets created by VTIL
#
add_library(vtil INTERFACE)

# Add `includes` to VTIL's include directory path
#
target_include_directories(vtil INTERFACE includes/)

# Mark all other VTIL targets as a dependency of VTIL
#
target_link_libraries(vtil INTERFACE architecture symex common optimizer) 