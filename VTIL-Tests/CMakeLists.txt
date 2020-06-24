project(VTIL-Tests)

add_executable(${PROJECT_NAME}
    doctest.h
    dummy.cpp
    main.cpp
)

target_link_libraries(${PROJECT_NAME} VTIL)
