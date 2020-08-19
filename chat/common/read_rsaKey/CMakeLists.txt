cmake_minimum_required (VERSION 3.5)

project (read_rsaKey VERSION 1.0.0)

add_executable(${PROJECT_NAME}
    ${PROJECT_SOURCE_DIR}/source/test.cpp
)

add_library(
    ReadRSAKey SHARED
    ${PROJECT_SOURCE_DIR}/source/read_rsaKey.cpp
)

find_package(OpenSSL)
if(OPENSSL_FOUND)
    target_link_libraries(ReadRSAKey
        PUBLIC OpenSSL::SSL
        PUBLIC OpenSSL::Crypto
    )
else()
    message(FATAL_ERROR, "Can't find OpenSSL")
endif()

target_include_directories(ReadRSAKey
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_include_directories(${PROJECT_NAME}
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE ReadRSAKey
)
