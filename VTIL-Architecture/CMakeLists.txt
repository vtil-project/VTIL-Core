project(VTIL-Architecture)

set(SOURCES arch/instruction_desc.cpp
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

add_library(${PROJECT_NAME} STATIC ${SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common VTIL-SymEx)
