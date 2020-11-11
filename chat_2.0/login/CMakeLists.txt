cmake_minimum_required(VERSION 3.5)

project(login)

add_executable(test
    ${PROJECT_SOURCE_DIR}/source/test.cpp
)

add_library(Login SHARED
    ${PROJECT_SOURCE_DIR}/source/login.cpp
)

target_include_directories(test
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_include_directories(Login
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(Login  -lmysqlpp
)

target_link_libraries(Login  -lpthread
)

target_link_libraries(Login ${PROJECT_SOURCE_DIR}/libs/libMessageRouter.so)

target_link_libraries(test
    PRIVATE Login
)
