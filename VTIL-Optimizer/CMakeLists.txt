project(VTIL-Optimizer)

add_library(${PROJECT_NAME} STATIC
    passes/normalize_stack.cpp
    passes/eliminate_dead.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common VTIL-SymEx VTIL-Architecture)
