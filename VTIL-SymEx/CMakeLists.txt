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
