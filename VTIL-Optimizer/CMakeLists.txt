project(VTIL-Optimizer)

add_library(${PROJECT_NAME} STATIC
    common/auxiliaries.cpp
    passes/stack_pinning_pass.cpp
    passes/istack_ref_substitution_pass.cpp
    passes/bblock_extension_pass.cpp
    passes/stack_propagation_pass.cpp
    passes/dead_code_elimination_pass.cpp
    passes/mov_propagation_pass.cpp
    passes/symbolic_rewrite_pass.cpp
    passes/opaque_predicate_elimination_pass.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common VTIL-SymEx VTIL-Architecture)
