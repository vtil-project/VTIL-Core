project(VTIL-SymEx VERSION 0.1.0)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS *.cpp *.hpp)
file(GLOB_RECURSE INCLUDES CONFIGURE_DEPENDS includes/*)

add_library(${PROJECT_NAME} STATIC
    ${SOURCES}
    ${INCLUDES}
)

source_group(TREE ${PROJECT_SOURCE_DIR} FILES ${SOURCES} ${INCLUDES})

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_link_libraries(${PROJECT_NAME} VTIL-Common)

if(MSVC)
    # /bigobj for reasons
    target_compile_options(${PROJECT_NAME} PRIVATE /bigobj)
endif()

configure_file(VTIL-SymEx.pc.in ${CMAKE_BINARY_DIR}/VTIL-SymEx.pc @ONLY)

if(VTIL_INSTALL)
    install(TARGETS ${PROJECT_NAME} DESTINATION lib)
    install(DIRECTORY includes/ DESTINATION include FILES_MATCHING PATTERN "*")
    install(FILES ${CMAKE_BINARY_DIR}/VTIL-SymEx.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
