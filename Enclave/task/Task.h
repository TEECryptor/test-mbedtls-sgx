//
// Created by nnn on 2022/10/27.
//

#ifndef TEE_TASKS_TASK_H
#define TEE_TASKS_TASK_H

#define TEST_HTTPS_REQUEST_TASK         1000
#define ENCRYPT_SECRET_KEY_TASK         1001
#define HMAC_SIGN_TASK                  1002
#define GET_BINANCE_COIN_ADDRESS_TASK   1003
#define DERIVE_EXTEND_PUBKEY_TASK       1004

#include <vector>
#include <string>
#include "nlohmann/json.hpp"

#define TEE_OK                                      0
#define TEE_OUT_ERROR_BASE                          10000
#define TEE_OUT_ERROR_PARAM_INVALID                 TEE_OUT_ERROR_BASE+1
#define TEE_OUT_ERROR_DATA_INVALID                  TEE_OUT_ERROR_BASE+2
#define TEE_OUT_ERROR_SIGN_FAILED                   TEE_OUT_ERROR_BASE+3
#define TEE_OUT_ERROR_VERIFY_FAILED                 TEE_OUT_ERROR_BASE+4
#define TEE_OUT_ERROR_ENCRYPT_FAILED                TEE_OUT_ERROR_BASE+5
#define TEE_OUT_ERROR_DECRYPT_FAILED                TEE_OUT_ERROR_BASE+6
#define TEE_OUT_ERROR_REQUEST_TO_EXCHANGE_FAILED    TEE_OUT_ERROR_BASE+7
#define TEE_OUT_ERROR_DERIVE_PUBKEY_FAILED          TEE_OUT_ERROR_BASE+8
#define TEE_OUT_ERROR_OCALL_FAILED                  TEE_OUT_ERROR_BASE+9
#define TEE_OUT_ERROR_MALLOC_FAILED                 TEE_OUT_ERROR_BASE+10
#define TEE_OUT_ERROR_UNEXPECTED                    TEE_OUT_ERROR_BASE+100



class Task {
public:
    virtual ~Task() = default;
    virtual int execute(const std::string &request, std::string &response) = 0;
    virtual uint32_t get_task_type( ) = 0;
};

class Dispatcher
{
public:
    int dispatch(uint32_t task_type, const std::string& request, std::string& reply);
    void register_task(Task* task);
    void unregister_task();

private:
    std::vector<Task *> m_vTask;

};
#endif //TEE_TASKS_TASK_H
