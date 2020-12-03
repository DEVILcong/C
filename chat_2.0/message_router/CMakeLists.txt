cmake_minimum_required(VERSION 3.5)

project(message_router)

add_library(MessageRouter SHARED
    ${PROJECT_SOURCE_DIR}/source/message_router.cpp
)

target_include_directories(MessageRouter
    PUBLIC ${PROJECT_SOURCE_DIR}/include
    PUBLIC ${PROJECT_SOURCE_DIR}/../include
)

target_link_libraries(MessageRouter 
    -ljsoncpp -lpthread -lssl -lcrypto
)
