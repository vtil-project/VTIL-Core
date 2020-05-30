project(VTIL-Architecture)

add_library(${PROJECT_NAME} STATIC
    arch/instruction_desc.cpp
    routine/basic_block.cpp
    routine/instruction.cpp
    routine/routine.cpp
    routine/serialization.cpp
    symex/pointer.cpp
    symex/variable.cpp
    symex/translation.cpp
    vm/interface.cpp
    vm/symbolic.cpp
    trace/cached_tracer.cpp
    trace/tracer.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common VTIL-SymEx)
