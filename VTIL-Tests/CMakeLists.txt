project(VTIL-Tests)

add_executable(${PROJECT_NAME}
    doctest.h
    main.cpp
    dummy.cpp
)

target_link_libraries(${PROJECT_NAME} VTIL)
