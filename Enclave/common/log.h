//
// Created by EDY on 2022/11/16.
//

#ifndef TEE_MPC_NODE_CPP_SGX_LOG_H
#define TEE_MPC_NODE_CPP_SGX_LOG_H

#include "Enclave_t.h"

#define LL_DEBUG 0
#define LL_INFO 1
#define LL_WARNING 2
#define LL_ERROR 3
#define LL_FATAL 4
#define LL_OUT_INFO 5

#define MAX_LOG_LEN   4096

#ifndef FUNC_BEGIN
#define FUNC_BEGIN DEBUG( "Begin!" )
#endif
#ifndef FUNC_END
#define FUNC_END DEBUG( "End!" )
#endif

// only output file name, but not full path in log
#define __FILENAME__ (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1):__FILE__)

#define DEBUG(format, args...)                                        \
    do{                                                               \
      char log[MAX_LOG_LEN] = {0};                                    \
      snprintf(log, MAX_LOG_LEN, "[%s(%d)]%s():", __FILENAME__, __LINE__, __FUNCTION__ ); \
      snprintf(log+strlen(log), MAX_LOG_LEN-strlen(log), format, ##args); \
      ocall_nlog(LL_DEBUG, log);                                          \
    }while(0)


#define INFO(format, args...)                                         \
    do{                                                               \
      char log[MAX_LOG_LEN] = {0};                                    \
      snprintf(log, MAX_LOG_LEN, "[%s(%d)]%s():", __FILENAME__, __LINE__, __FUNCTION__ ); \
      snprintf(log+strlen(log), MAX_LOG_LEN-strlen(log), format, ##args); \
      ocall_nlog(LL_INFO, log);                                          \
    }while(0)


#define INFO_OUTPUT_CONSOLE(format, args...)        \
    do{                                                               \
      char log[MAX_LOG_LEN] = {0};                                    \
      snprintf(log, MAX_LOG_LEN, "[%s(%d)]%s():", __FILENAME__, __LINE__, __FUNCTION__ ); \
      snprintf(log+strlen(log), MAX_LOG_LEN-strlen(log), format, ##args); \
      ocall_nlog(LL_OUT_INFO, log);                                          \
    }while(0)

#define WARN(format, args...)        \
    do{                                                               \
      char log[MAX_LOG_LEN] = {0};                                    \
      snprintf(log, MAX_LOG_LEN, "[%s(%d)]%s():", __FILENAME__, __LINE__, __FUNCTION__ ); \
      snprintf(log+strlen(log), MAX_LOG_LEN-strlen(log), format, ##args); \
      ocall_nlog(LL_WARNING, log);                                          \
    }while(0)

#define ERROR(format, args...)        \
    do{                                                               \
      char log[MAX_LOG_LEN] = {0};                                    \
      snprintf(log, MAX_LOG_LEN, "[%s(%d)]%s():", __FILENAME__, __LINE__, __FUNCTION__ ); \
      snprintf(log+strlen(log), MAX_LOG_LEN-strlen(log), format, ##args); \
      ocall_nlog(LL_ERROR, log);                                          \
    }while(0)


#endif //TEE_MPC_NODE_CPP_SGX_LOG_H
