cmake_minimum_required(VERSION 3.20)
project(lintel_host_tests CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Same mbedTLS line that ESP-IDF v5.4 ships, so host and target share the crypto code.
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.3/mbedtls-3.6.3.tar.bz2
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mbedtls googletest)

if(DEFINED LINTEL_SANITIZE AND LINTEL_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../components/lintel_core lintel_core)

add_executable(lintel_tests
    test_crypto.cpp
    test_frame.cpp
    test_counters.cpp
    test_sdm.cpp
    test_messages.cpp
    test_policy.cpp
    test_audit.cpp
    test_link.cpp
    test_system.cpp
    test_adopt.cpp
)
target_link_libraries(lintel_tests PRIVATE lintel_core GTest::gtest_main)

enable_testing()
include(GoogleTest)
gtest_discover_tests(lintel_tests)
