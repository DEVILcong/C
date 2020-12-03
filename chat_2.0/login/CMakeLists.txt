cmake_minimum_required(VERSION 3.5)

project(login)

add_library(Login SHARED
    ${PROJECT_SOURCE_DIR}/source/login.cpp
)

target_include_directories(Login
    PUBLIC ${PROJECT_SOURCE_DIR}/include
    PUBLIC ${PROJECT_SOURCE_DIR}/../include
)

target_link_libraries(Login  
    -lpthread -lsqlite3 -lssl -lcrypto -ljsoncpp
    ${PROJECT_SOURCE_DIR}/../libs/libProcessMsg.so    
)



