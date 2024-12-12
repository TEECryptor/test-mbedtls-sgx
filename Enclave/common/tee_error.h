//
// Created by EDY on 2022/11/17.
//

#ifndef TEE_ERROR_H
#define TEE_ERROR_H

#define TEE_OK 0 //!< No error
#define TEE_ERROR_BASE                          200000
#define TEE_ERROR_INTERNAL_ERROR                TEE_ERROR_BASE + 1  /* encounter an internal error */
#define TEE_ERROR_FAILED_TO_LOAD_CONFIGURE      TEE_ERROR_BASE + 2  /* failed to load enclave configure file in enclave initialize */
#define TEE_ERROR_FAILED_TO_DECRYPT_REQUEST     TEE_ERROR_BASE + 3  /* failed to decrypt the request by tls private key */
#define TEE_ERROR_FAILED_TO_DISPATCH_REQUEST    TEE_ERROR_BASE + 4  /* failed to dispatch the request, maybe it has a wrong format */
#define TEE_ERROR_FAILED_TO_LOAD_REMOTE_PUBKEY  TEE_ERROR_BASE + 5  /* failed to load the remote public key in request */
#define TEE_ERROR_FAILED_TO_ENCRYPT_RESULT      TEE_ERROR_BASE + 6  /* failed to encrypt the result data by tls public key */
#define TEE_ERROR_FAILED_TO_MALLOC              TEE_ERROR_BASE + 7  /* failed to call malloc api */
#define TEE_ERROR_ENCOUNTERED_EXCEPTION         TEE_ERROR_BASE + 8  /* encounter an exception */
#define TEE_ERROR_INVALID_PARAM                 TEE_ERROR_BASE + 9  /* function input parameters are invalid */
#define TEE_ERROR_INVALID_CALL                  TEE_ERROR_BASE + 10 /* this call is invalid, maybe it's called in a wrong order */
#define TEE_ERROR_BUFFER_TOO_SMALL              TEE_ERROR_BASE + 11 /* the output buffer is too small */
#define TEE_ERROR_ALG_NOTSUPPORT                TEE_ERROR_BASE + 12 /* the specified algorith is not support */
#define TEE_ERROR_FUNCTION_NOTSUPPORT           TEE_ERROR_BASE + 13 /* this function is not supported yet */
#define TEE_ERROR_FILE_NOT_EXIST                TEE_ERROR_BASE + 14
#define TEE_ERROR_CREATE_FILE_FAILED            TEE_ERROR_BASE + 15
#define TEE_ERROR_GET_FILESIZE_FAILED           TEE_ERROR_BASE + 16
#define TEE_ERROR_FILE_IS_EMPTY                 TEE_ERROR_BASE + 17
#define TEE_ERROR_READ_FILE_FAILED              TEE_ERROR_BASE + 18
#define TEE_ERROR_WRITE_FILE_FAILED             TEE_ERROR_BASE + 19
#define TEE_ERROR_UNSEAL_INVALID_SIGNATURE      TEE_ERROR_BASE + 20
#define TEE_ERROR_ECC_GEN_FAILED                TEE_ERROR_BASE + 21
#define TEE_ERROR_ECC_ENCRYPT_FAILED            TEE_ERROR_BASE + 22
#define TEE_ERROR_ECC_DECRYPT_FAILED            TEE_ERROR_BASE + 23
#define TEE_ERROR_ECC_INVALID_SIGNATURE         TEE_ERROR_BASE + 24
#define TEE_ERROR_BASE64_DECODE_FAILED          TEE_ERROR_BASE + 31
#define TEE_ERROR_BASE64_ENCODE_FAILED          TEE_ERROR_BASE + 32
#define TEE_ERROR_SYMM_ENCRYPT_FAILED           TEE_ERROR_BASE + 33
#define TEE_ERROR_SYMM_DECRYPT_FAILED           TEE_ERROR_BASE + 34
#define TEE_ERROR_EXPORT_PUBKEY_FAILED          TEE_ERROR_BASE + 35
#define TEE_ERROR_CONSOLE_INPUT_FAILED          TEE_ERROR_BASE + 36
#define TEE_ERROR_START_CACHE_THREAD_FAILED     TEE_ERROR_BASE + 37
#define TEE_ERROR_START_SESSION_THREAD_FAILED   TEE_ERROR_BASE + 38
#define TEE_ERROR_DERIVATION_KEY_FAILED         TEE_ERROR_BASE + 39
#define TEE_ERROR_CREATE_SYMMKEY_FAILED         TEE_ERROR_BASE + 40
#define TEE_ERROR_CREATE_REPORT_FAILED          TEE_ERROR_BASE + 41
#define TEE_ERROR_CA_REPORT_VERIFY_FAILED       TEE_ERROR_BASE + 42
#define TEE_ERROR_CA_MRENCLAVESIG_VERIFY_FAILED TEE_ERROR_BASE + 43
#define TEE_ERROR_DECRYPT_ROOTKEY_FAILED        TEE_ERROR_BASE + 44
#define TEE_ERROR_READ_CONFIG_FAILED            TEE_ERROR_BASE + 45
#define TEE_ERROR_VERIFY_MERENCLAVE_SIG_FAILED  TEE_ERROR_BASE + 46
#define TEE_ERROR_FAILED_TO_CALL_OCALL          TEE_ERROR_BASE + 47
#define TEE_ERROR_FAILED_TO_AUTHORISE           TEE_ERROR_BASE + 48
#define TEE_ERROR_INVALID_LICENSE               TEE_ERROR_BASE + 49
#define TEE_ERROR_INVALID_LICENSE_SIG           TEE_ERROR_BASE + 50
#define TEE_ERROR_LICENSE_STATUS_NOEFFECTIVE    TEE_ERROR_BASE + 51
#define TEE_ERROR_LICENSE_STATUS_INVALID        TEE_ERROR_BASE + 52
#define TEE_ERROR_LICENSE_STATUS_EXPIRED        TEE_ERROR_BASE + 53
#define TEE_ERROR_LICENSE_PLATFORM_INVALID      TEE_ERROR_BASE + 54
#define TEE_ERROR_LICENSE_ALG_INVALID           TEE_ERROR_BASE + 55
#define TEE_ERROR_LICENSE_PROTOCOL_INVALID      TEE_ERROR_BASE + 56
#define TEE_ERROR_LICENSE_CURVE_INVALID         TEE_ERROR_BASE + 57
#define TEE_ERROR_LICENSE_THRESHOLD_INVALID     TEE_ERROR_BASE + 58
#define TEE_ERROR_LICENSE_BIP44PATH_INVALID     TEE_ERROR_BASE + 59
#define TEE_ERROR_START_TIMESTAMP_THREAD_FAILED TEE_ERROR_BASE + 60
#define TEE_ERROR_FAILED_TO_VALIDATE_TIME       TEE_ERROR_BASE + 61


const char * t_strerror( int error_code );

#endif //TEE_ERROR_H
