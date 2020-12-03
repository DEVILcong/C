cmake_minimum_required(VERSION 3.5)

project(chat VERSION 2.0)

add_subdirectory(login)
add_subdirectory(message_router)

add_executable(chat_server main.cpp)

target_include_directories(chat_server
    PRIVATE ${PROJECT_SOURCE_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/login/include
    PRIVATE ${PROJECT_SOURCE_DIR}/message_router/include
)

target_link_libraries(chat_server
    Login MessageRouter
)