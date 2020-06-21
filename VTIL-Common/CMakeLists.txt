project(VTIL-Common)

add_library(${PROJECT_NAME} STATIC
    amd64/assembler.cpp
    amd64/disassembler.cpp
    amd64/register_details.cpp
    io/logger.cpp
    math/operators.cpp
    util/critical_section.cpp
    util/variant.cpp
    formats/winpe.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC includes)

# Common needs Capstone & Keystone
target_link_libraries(${PROJECT_NAME} capstone-static keystone)
