cmake_minimum_required(VERSION 3.5)

project(make_rsaKey VERSION 1.0.0)

add_executable(${PROJECT_NAME}
    ${PROJECT_SOURCE_DIR}/source/test.cpp
)

add_library(MakeRSAKey SHARED
    ${PROJECT_SOURCE_DIR}/source/make_rsaKey.cpp
)

target_include_directories(MakeRSAKey
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_include_directories(${PROJECT_NAME}
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE MakeRSAKey
)

find_package(OpenSSL)
if(OPENSSL_FOUND)
    target_link_libraries(MakeRSAKey
        PUBLIC OpenSSL::SSL
        PUBLIC OpenSSL::Crypto
    )
else()
    message(FATAL_ERROR "Can't find OpenSSL")
endif()
