cmake_minimum_required(VERSION 3.0)

project(school_tools)

#主函数所在，测试库是否正常运行
add_executable(test
    ${PROJECT_SOURCE_DIR}/source/test.cpp
)

#实现主要功能的库
add_library(SchoolTools SHARED
    ${PROJECT_SOURCE_DIR}/source/school_tools.cpp
)

target_include_directories(test
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_include_directories(SchoolTools
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(test
    PRIVATE SchoolTools
)

#用于字符编码转换的库 UTF-8转GBK
target_link_libraries(SchoolTools
    PUBLIC ${PROJECT_SOURCE_DIR}/libs/libCharacterConvert.so
)

#连接libcurl
find_package(CURL)
if(CURL_FOUND)
    target_link_libraries(SchoolTools
        PUBLIC ${CURL_LIBRARIES}
    )
else()
    message(FATAL_ERROR, "can't find curl")
endif()
