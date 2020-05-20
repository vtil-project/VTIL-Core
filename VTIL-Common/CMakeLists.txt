# VTIL-Common target
#

set(common_SOURCES amd64/assembler.cpp
    amd64/disassembler.cpp
    amd64/register_details.cpp
    io/logger.cpp
    math/operators.cpp
    util/critical_section.cpp
    util/variant.cpp
)

add_library(common STATIC ${common_SOURCES})
target_include_directories(common PUBLIC "./includes")

# Common needs Capstone & Keystone
target_link_libraries(common capstone-static keystone)
