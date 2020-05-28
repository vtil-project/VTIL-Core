project(VTIL-SymEx)

set(SOURCES directives/directive.cpp
    directives/transformer.cpp
    expressions/expression.cpp
    expressions/unique_identifier.cpp
    simplifier/simplifier.cpp
)

add_library(${PROJECT_NAME} STATIC ${SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common)
