project(VTIL-SymEx)

add_library(${PROJECT_NAME} STATIC
    directives/directive.cpp
    directives/transformer.cpp
    expressions/expression.cpp
    expressions/unique_identifier.cpp
    simplifier/simplifier.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common)
