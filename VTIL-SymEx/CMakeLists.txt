# VTIL-SymEx target
#

set(symex_SOURCES directives/directive.cpp
    directives/transformer.cpp
    expressions/expression.cpp
    expressions/unique_identifier.cpp
    simplifier/simplifier.cpp
)

add_library(symex STATIC ${symex_SOURCES})
target_include_directories(symex PUBLIC "./includes")
target_link_libraries(symex common)
set_property(TARGET symex PROPERTY CXX_STANDARD 20)
set_property(TARGET symex PROPERTY CXX_STANDARD_REQUIRED ON)

# Add -fpermissive on MSVC
if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(common PUBLIC -fpermissive)
endif()