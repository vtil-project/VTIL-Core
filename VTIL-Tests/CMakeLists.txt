project(VTIL-Tests)

set(SOURCES doctest.h
    main.cpp
    dummy.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} VTIL)
