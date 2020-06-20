project(VTIL-Compiler)

add_library(${PROJECT_NAME} STATIC
    common/auxiliaries.cpp
    optimizer/stack_pinning_pass.cpp
    optimizer/istack_ref_substitution_pass.cpp
    optimizer/bblock_extension_pass.cpp
    optimizer/stack_propagation_pass.cpp
    optimizer/dead_code_elimination_pass.cpp
    optimizer/mov_propagation_pass.cpp
    optimizer/symbolic_rewrite_pass.cpp
    optimizer/branch_correction_pass.cpp
    optimizer/register_renaming_pass.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common VTIL-SymEx VTIL-Architecture)
