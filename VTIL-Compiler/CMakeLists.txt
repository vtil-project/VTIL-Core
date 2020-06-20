project(VTIL-Compiler)

add_library(${PROJECT_NAME} STATIC
    common/auxiliaries.cpp
    optimization/stack_pinning_pass.cpp
    optimization/istack_ref_substitution_pass.cpp
    optimization/bblock_extension_pass.cpp
    optimization/stack_propagation_pass.cpp
    optimization/dead_code_elimination_pass.cpp
    optimization/mov_propagation_pass.cpp
    optimization/symbolic_rewrite_pass.cpp
    optimization/branch_correction_pass.cpp
    optimization/register_renaming_pass.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common VTIL-SymEx VTIL-Architecture)
