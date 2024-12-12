#include "Enclave.h"
#include "Enclave_t.h"
#include "log.h"
#include "sgx_trts.h"
#include "sgx_lfence.h"
#include "task/Task.h"
//
#include "task/HttpsRequestTask.h"

Dispatcher g_dispatcher;

#define MAX_BUF_LEN  4*1024

int printf( const char* fmt, ... ) {
    char buf[MAX_BUF_LEN] = { '\0' };
    va_list ap;
    va_start( ap, fmt );
    vsnprintf( buf, MAX_BUF_LEN, fmt, ap );
    va_end( ap );
    ocall_printf( buf );
    return (int)strnlen( buf, MAX_BUF_LEN - 1 ) + 1;
}

int err_msg_ret(int err_code, const std::string &err_msg, std::string &out)
{
    char error_code_str[32] = {0};
    const char* err_code_proxy = "M1";

    snprintf(error_code_str, sizeof(error_code_str), "%s%d", err_code_proxy, err_code);

    nlohmann::json err_json;
    err_json["code"] = error_code_str;
    err_json["message"] = err_msg;
    out = err_json.dump();
    return err_code;
}

void* malloc_outside( size_t size ) {
    if(size == 0) return nullptr;

    uint8_t* outside_buf = nullptr;
    sgx_status_t status = ocall_malloc(size, &outside_buf);
    if (status != SGX_SUCCESS || !outside_buf) return nullptr;

    if ( sgx_is_outside_enclave(outside_buf, size) != 1 ) {
        throw std::runtime_error(std::string("Failed in sgx_is_outside_enclave in func malloc_outside (error code: ") + std::to_string(status) + ")");
    }

    sgx_lfence();

    memset(outside_buf, 0, size);

    return outside_buf;
}


// Execute a TEE task in enclave
int ecall_run(
    uint32_t type, 
    const char* input_data,
    uint64_t data_len,
    char **output, 
    uint64_t *output_len)
{
    int ret = 0;
    size_t response_data_size = 0;
    std::string request_data;
    std::string response_data;
    std::string error_msg;
    uint8_t* outside_buff = nullptr;

    FUNC_BEGIN;

    if (!input_data || data_len <= 0) {
        ERROR("input_data or data_len is null");
        return TEE_OUT_ERROR_PARAM_INVALID;
    }
    if (!output || !output_len) {
        ERROR("output or output_len is null");
        return TEE_OUT_ERROR_PARAM_INVALID;
    }
    request_data = std::string(input_data, data_len);

    //INFO("==>type: %d", type);
    //INFO("==>Request: %s\n", request_data_b64.c_str());

    // Dispatch requests
    try {
        Test::HttpsRequestTask task;
        ret = task.execute(request_data, response_data);
        if (response_data.empty()) {
            ERROR("response data is empty");
            ret = err_msg_ret(TEE_OUT_ERROR_UNEXPECTED, "response data is empty", response_data);
        }
    } catch (std::exception &e) {
        ERROR("g_dispatcher.dispatch(() encounter an exception! error: %s", e.what() );
        ret = err_msg_ret(TEE_OUT_ERROR_UNEXPECTED, e.what(), response_data);
    }

    // Allocate a block of untrusted memory to pass the result from enclave to app
    response_data_size = response_data.length();
    outside_buff = (uint8_t*)malloc_outside(response_data_size + 1);
    if (!outside_buff) {
        ERROR("Failed to call malloc_outside()! size: %ld", response_data_size + 1);
        return TEE_OUT_ERROR_MALLOC_FAILED;
    }
    memset(outside_buff, 0, response_data_size + 1);
    memcpy(outside_buff, response_data.c_str(), response_data_size);
    *output = (char*)outside_buff;
    *output_len = response_data_size;

    FUNC_END;

    return ret;
}
