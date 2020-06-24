project(VTIL-Compiler)

add_library(${PROJECT_NAME} STATIC
    common/apply_all.hpp
    common/auxiliaries.cpp
    common/auxiliaries.hpp
    common/interface.hpp
    optimizer/bblock_extension_pass.cpp
    optimizer/bblock_extension_pass.hpp
    optimizer/branch_correction_pass.cpp
    optimizer/branch_correction_pass.hpp
    optimizer/dead_code_elimination_pass.cpp
    optimizer/dead_code_elimination_pass.hpp
    optimizer/istack_ref_substitution_pass.cpp
    optimizer/istack_ref_substitution_pass.hpp
    optimizer/mov_propagation_pass.cpp
    optimizer/mov_propagation_pass.hpp
    optimizer/register_renaming_pass.cpp
    optimizer/register_renaming_pass.hpp
    optimizer/stack_pinning_pass.cpp
    optimizer/stack_pinning_pass.hpp
    optimizer/stack_propagation_pass.cpp
    optimizer/stack_propagation_pass.hpp
    optimizer/symbolic_rewrite_pass.cpp
    optimizer/symbolic_rewrite_pass.hpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common VTIL-SymEx VTIL-Architecture)
