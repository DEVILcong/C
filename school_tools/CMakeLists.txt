cmake_minimum_required(VERSION 3.0)

project(school_tools)

add_executable(test
    ${PROJECT_SOURCE_DIR}/source/test.cpp
)

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

target_link_libraries(SchoolTools
    PUBLIC ${PROJECT_SOURCE_DIR}/libs/libCharacterConvert.so
)

find_package(CURL)
if(CURL_FOUND)
    target_link_libraries(SchoolTools
        PUBLIC ${CURL_LIBRARIES}
    )
else()
    message(FATAL_ERROR, "can't find curl")
endif()
