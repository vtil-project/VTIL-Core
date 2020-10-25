project(VTIL VERSION 0.1.0)

# This builds no sources -- it simply aliases a collection of all other targets created by VTIL
#
add_library(${PROJECT_NAME} INTERFACE)

# Add `includes` to VTIL's include directory path
#
target_include_directories(${PROJECT_NAME} INTERFACE includes)

# Mark all other VTIL targets as a dependency of VTIL
#
target_link_libraries(${PROJECT_NAME} INTERFACE VTIL-Architecture VTIL-SymEx VTIL-Common VTIL-Compiler)

configure_file(VTIL.pc.in ${CMAKE_BINARY_DIR}/VTIL.pc @ONLY)

if(VTIL_INSTALL)
    install(DIRECTORY includes/ DESTINATION include FILES_MATCHING PATTERN "*")
    install(FILES ${CMAKE_BINARY_DIR}/VTIL.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
