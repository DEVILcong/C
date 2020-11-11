cmake_minimum_required(VERSION 3.5)

project(message_router)

add_executable(test
    ${PROJECT_SOURCE_DIR}/source/test.cpp
)

target_include_directories(test
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

add_library(MessageRouter SHARED
    ${PROJECT_SOURCE_DIR}/source/message_router.cpp
)

target_include_directories(MessageRouter
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(MessageRouter -lmysqlpp -ljsoncpp)
target_link_libraries(test PRIVATE MessageRouter)