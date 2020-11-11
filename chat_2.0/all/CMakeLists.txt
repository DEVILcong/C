cmake_minimum_required(VERSION 3.5)

project(chat_server)

add_executable(chat_server
    ${PROJECT_SOURCE_DIR}/src/main.cpp
)

target_include_directories(chat_server
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(chat_server
    ${PROJECT_SOURCE_DIR}/libs/libLogin.so
    ${PROJECT_SOURCE_DIR}/libs/libMessageRouter.so
    -lpthread
)