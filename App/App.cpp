#include "App.h"
#include "Enclave_u.h"
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <sgx_urts.h>
#include <thread>
#include <list>
#include <nlohmann/json.hpp>
#include "test_data.h"

sgx_enclave_id_t global_eid = 0;

void printHex(const uint8_t* data, size_t size) 
{
    for (size_t i = 0; i < size; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int do_https_get(const std::string &url, const std::string &ca_certs, const std::list<std::string> &headers, std::string &reponse) 
{
    int ret = 0;
    sgx_status_t sgx_status;
    char* resp_body_buf = nullptr;
    uint64_t resp_body_buf_len;
    nlohmann::json header_json;
    nlohmann::json req_json;
    nlohmann::json reply_json;
    std::string request;

    for (std::string header : headers) {
        header_json.push_back(header);
    }

    req_json["url"] = url;
    req_json["certs"] = ca_certs;
    req_json["method"] = "GET";
    req_json["headers"] = header_json;
    request = req_json.dump();

    sgx_status = ecall_run(global_eid, &ret, 1,
                           request.c_str(), request.length(), 
                           &resp_body_buf, &resp_body_buf_len);
    if (sgx_status != SGX_SUCCESS) {
        printf("--->Function ecall_enclave_init() failed, error: 0x%x\n", sgx_status);
        goto _exit;
    }
    if (0 != ret) {
        printf("--->Function ecall_enclave_init() failed, ret: %d\n", ret);
        goto _exit;
    }

    reponse = std::string(resp_body_buf, resp_body_buf_len);
_exit:
    if (resp_body_buf) {
        delete []resp_body_buf;
        resp_body_buf = nullptr;
    }
    return ret;
}

int do_https_post(const std::string &url, const std::string &ca_certs, const std::list<std::string> &headers, const std::string &body, std::string &reponse) 
{
    int ret = 0;
    sgx_status_t sgx_status;

    return ret;
}

void test_world_time_url()
{
    int ret = 0;
    std::list<std::string> headers;
    std::string response;

    printf("\nTest world time url: %s\n", world_time_url);

    if ((ret = do_https_get(world_time_url, world_time_ca_certs, headers, response)) != 0) {
        printf("--->ERROR: do_https_get() failed! ret: %d\n", ret);
    }

    printf("Reponse: %s\n", response.c_str());
}

void test_binance_api()
{
    int ret = 0;
    std::list<std::string> headers;
    std::string response;

    printf("\nTest binance api url: %s\n", binance_url);

	headers.push_back("X-MBX-APIKEY: 0HU6mrraPEEayWmGq1OWK7B5zVNNXbuoracMkFNDosDtTT2JJ44Rob1JxeOXSpBb");

    if ((ret = do_https_get(binance_url, binance_ca_certs, headers, response)) != 0) {
        printf("--->ERROR: do_https_get() failed! ret: %d\n", ret);
    }

    printf("Reponse: %s\n", response.c_str());
}


int SGX_CDECL main(int argc, char *argv[])
{
    int ret = 0;
    sgx_status_t sgx_status;

    // Initialize enclave
    printf( "Try to create Enclave ...\n" );
    sgx_status = sgx_create_enclave( (const char*)argv[1], 0, nullptr, nullptr, &global_eid, nullptr );
    if (sgx_status != SGX_SUCCESS ) {
        printf("--->Initialize enclave failed! enclave file: %s, error: %d\n", argv[1], sgx_status);
        goto _exit;
    }
    printf( "Enclave is created!\n");

    printf( "\nStart to test...\n");

    test_world_time_url();

    test_binance_api();

    printf( "\nTest finished!\n\n" );

_exit:
    sgx_destroy_enclave( global_eid );
    printf( "End!\n");

    return ret;
}
