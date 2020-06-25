project(VTIL-SymEx)

add_library(${PROJECT_NAME} STATIC
    directives/directive.cpp
    directives/directive.hpp
    directives/fast_matcher.hpp
    directives/transformer.cpp
    directives/transformer.hpp
    expressions/expression.cpp
    expressions/expression.hpp
    expressions/unique_identifier.cpp
    expressions/unique_identifier.hpp
    simplifier/boolean_directives.cpp
    simplifier/boolean_directives.hpp
    simplifier/directives.hpp
    simplifier/simplifier.cpp
    simplifier/simplifier.hpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common)
