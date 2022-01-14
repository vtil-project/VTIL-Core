# Extract project name from folder
get_filename_component(PROJECT_NAME ${CMAKE_CURRENT_LIST_DIR} NAME)
string(REPLACE " " "_" PROJECT_NAME "${PROJECT_NAME}")

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS *.cpp *.hpp *.h)

add_executable(${PROJECT_NAME}
	${SOURCES}
)

source_group(TREE ${PROJECT_SOURCE_DIR} FILES ${SOURCES})

target_link_libraries(${PROJECT_NAME} VTIL)
