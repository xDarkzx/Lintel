# lintel_core builds two ways: as an ESP-IDF component inside the firmware
# projects, and as a plain static library for the host test suite.
set(LINTEL_CORE_SRCS
    src/audit.cpp
    src/controller.cpp
    src/counters.cpp
    src/crypto.cpp
    src/door_node.cpp
    src/frame.cpp
    src/link.cpp
    src/messages.cpp
    src/policy.cpp
    src/sdm.cpp
)

if(ESP_PLATFORM)
    idf_component_register(SRCS ${LINTEL_CORE_SRCS}
                           INCLUDE_DIRS include
                           REQUIRES mbedtls)
    return()
endif()

add_library(lintel_core STATIC ${LINTEL_CORE_SRCS})
target_include_directories(lintel_core PUBLIC include)
target_compile_features(lintel_core PUBLIC cxx_std_17)
target_link_libraries(lintel_core PUBLIC MbedTLS::mbedcrypto)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(lintel_core PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror
                                               -Wno-sign-conversion)
endif()
