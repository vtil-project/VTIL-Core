# VTIL-Architecture target
#

set(architecture_SOURCES arch/instruction_desc.cpp
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

add_library(architecture STATIC ${architecture_SOURCES})
target_include_directories(architecture PUBLIC "./includes")
target_link_libraries(architecture common)
target_link_libraries(architecture symex)
