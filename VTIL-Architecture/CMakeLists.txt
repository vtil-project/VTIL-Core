project(VTIL-Architecture)

add_library(${PROJECT_NAME} STATIC
    arch/instruction_desc.cpp
    arch/instruction_desc.hpp
    arch/instruction_set.hpp
    arch/operands.hpp
    arch/register_desc.hpp
    arch/identifier.hpp
    misc/debug.hpp
    routine/basic_block.cpp
    routine/basic_block.hpp
    routine/call_convention.hpp
    routine/instruction.cpp
    routine/instruction.hpp
    routine/routine.cpp
    routine/routine.hpp
    routine/serialization.cpp
    routine/serialization.hpp
    symex/batch_translator.hpp
    symex/memory.hpp
    symex/pointer.cpp
    symex/pointer.hpp
    symex/translation.cpp
    symex/translation.hpp
    symex/variable.cpp
    symex/variable.hpp
    trace/cached_tracer.cpp
    trace/cached_tracer.hpp
    trace/tracer.cpp
    trace/tracer.hpp
    vm/interface.cpp
    vm/interface.hpp
    vm/lambda.hpp
    vm/symbolic.cpp
    vm/symbolic.hpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common VTIL-SymEx)
