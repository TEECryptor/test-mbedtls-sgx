# Set all flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -nostdinc++")

message(STATUS "CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}")

# Don't use stream!!
add_definitions(-DJSON_NO_IO)

# Don't use locale convert function
add_definitions(-DJSON_NO_LOCALE)

# Set source code files
set(ENCLAVE_SRC_FILES 
        Enclave.cpp
        task/Task.cpp
        task/HttpsRequestTask.cpp

        https_client/https_client.cpp
        https_client/https_request.cpp
        https_client/https_response.cpp
        https_client/https_url.cpp
)

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(OUTPUT Enclave_t.h Enclave_t.c
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.edl
        COMMAND ${SGX_EDGER8R} --trusted ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.edl
        --search-path ${SGX_SDK}/include 
        --search-path ${MBEDTLS_SGX_DIR}/lib
)
message(STATUS "COMMAND: ${SGX_EDGER8R} --trusted ${CMAKE_SOURCE_DIR}/Enclave.edl")

# Build enclave.so
add_library(enclave SHARED
        ${ENCLAVE_SRC_FILES}
        ${CMAKE_CURRENT_BINARY_DIR}/Enclave_t.c
)

# Additional include paths
include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${MBEDTLS_SGX_DIR}/include
        ${CMAKE_SOURCE_DIR}/Enclave
        ${CMAKE_SOURCE_DIR}/Enclave/common
        ${CMAKE_SOURCE_DIR}/Enclave/https_client
        ${CMAKE_SOURCE_DIR}/third_party
        ${SGX_SDK}/include
        ${SGX_SDK}/include/tlibc
        ${SGX_SDK}/include/libcxx
)
# Needed for the generated file Enclave_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# No "lib" prefix for output file name
set_target_properties(enclave PROPERTIES PREFIX "")
        
# Link flags
target_link_libraries(enclave "${SGX_COMMON_CFLAGS} \
        -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
        -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
        -Wl,--start-group ${MBEDTLS_SGX_LIB_FILE_T} -lsgx_pthread -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tprotected_fs -l${SGX_TSVC_LIB} -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined  \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
        -Wl,--defsym,__ImageBase=0"
)

# Sign enclave (use the same private key to sign enclave.so)
add_custom_command(TARGET enclave
        POST_BUILD
        COMMAND ${SGX_ENCLAVE_SIGNER} sign
        -key ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_private_test.pem
        -config ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml
        -enclave enclave.so
        -out enclave.signed.so
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
message(STATUS "COMMAND: ${SGX_ENCLAVE_SIGNER} signing enclave.so => ${CMAKE_CURRENT_BINARY_DIR}/enclave.signed.so")

# Install target file
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/enclave.signed.so
        DESTINATION ./
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

message(STATUS "\n\n")
