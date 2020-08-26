cmake_minimum_required(VERSION 3.5)

project(character_convert)

add_executable(test
    ${PROJECT_SOURCE_DIR}/source/test.cpp
)

add_library(CharacterConvert SHARED
    ${PROJECT_SOURCE_DIR}/source/character_convert.cpp
)

target_include_directories(test
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_include_directories(CharacterConvert
    PUBLIC $(PROJECT_SOURCE_DIR)/include
)

target_link_libraries(test
    PRIVATE CharacterConvert
)

target_link_libraries(CharacterConvert
    PUBLIC iconv
)
