cmake_minimum_required(VERSION 3.20)
project(test-mbedtls_SGX "C" "CXX")
set(PROJECT_VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_COMPILER "/usr/bin/gcc")
set(CMAKE_CXX_COMPILER "/usr/bin/g++")

set(SGX_SDK "/opt/intel/sgxsdk")
set(SGX_ARCH x64)

# Set path and file name for mbedtls_SGX
set(MBEDTLS_SGX_DIR "/opt/mbedtls_SGX-2.6.0")
set(MBEDTLS_SGX_LIB_FILE_T "${MBEDTLS_SGX_DIR}/lib/libmbedtls_SGX_t.a")
set(MBEDTLS_SGX_LIB_FILE_U "${MBEDTLS_SGX_DIR}/lib/libmbedtls_SGX_u.a")
message(STATUS "MBEDTLS_SGX_LIB_FILE_T = ${MBEDTLS_SGX_LIB_FILE_T}")
message(STATUS "MBEDTLS_SGX_LIB_FILE_U = ${MBEDTLS_SGX_LIB_FILE_U}")

if(${USE_SIM_MODE})
        set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW")
        set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")
else ()
        set(SGX_MODE HW CACHE STRING "SGX mode: SIM or HW")
        set(SGX_BUILD RELEASE CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")
endif()
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ")

option(DEBUG "option for debug" OFF)
if (DEBUG)
        set(CMAKE_BUILD_TYPE "Debug")
        add_definitions(-DDEBUG -UNDEBUG -UEDEBUG)
else ()
        set(CMAKE_BUILD_TYPE "Release")
        add_definitions(-DNDEBUG -UEDEBUG -UDEBUG)
endif ()

include (cmake/Init.cmake)
include (cmake/ConfigSGX.cmake)

set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/${PROJECT_NAME}-${PROJECT_VERSION})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

add_subdirectory(App)
add_subdirectory(Enclave)

message(STATUS "CMAKE_CURRENT_SOURCE_DIR = ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "CMAKE_CURRENT_BINARY_DIR = ${CMAKE_CURRENT_BINARY_DIR}")
message(STATUS "\n\n")