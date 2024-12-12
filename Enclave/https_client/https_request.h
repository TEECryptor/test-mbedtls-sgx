/*************************************************
 * File name : HttpsRequest.h
 * Introduce : HTTPS/HTTP request class, this class
 *             use library mbedtls to do a HTTPS/HTTP
 *             request.
 * Create: 2021-6-9 by yyf
 * 
 *************************************************/

#ifndef _HTTPS_REQUEST_H_
#define _HTTPS_REQUEST_H_

#include "https_client.h"
#include "https_url.h"
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <list>

#define DEBUG_LEVEL      0
#define DEFAULT_TIMEOUT  5000
#define DATA_BUF_SIZE    4 * 1024
#define SEED_PERS       "mbedtls_https_client"

/**
 * @brief HTTP header for response
 * 
 */
typedef struct {
    int status;
    long content_length;
    bool keepAlive;
} HTTP_HEADER;

/**
 * @brief request content
 * 
 */
typedef struct {
    HttpsUrl url;
    std::string method;
    std::string body;
} HTTP_REQUEST;

/**
 * @brief response content
 * 
 */
typedef struct {
    HTTP_HEADER header;
    std::string body;
} HTTP_RESPONSE;

/**
 * @brief ssl context for mbedtls
 * 
 */
typedef struct {
    mbedtls_net_context ssl_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca_cert;
} HTTP_SSL;

/**
 * @brief context for a HTTP/HTTPS connection
 * 
 */
typedef struct {
    HTTPS_SETTING cfg;
    //
    HTTP_SSL tls;
    HTTP_REQUEST resquest;
    HTTP_RESPONSE response;
} HTTP_CONTEXT;

/**
 * HTTPS request class, which implement
 * a GET/POST request to host, support
 * HTTP/HTTPS protocol
 * 
 */
class HttpsRequest : IHttpsRequest {
public:
    HttpsRequest();
    virtual ~HttpsRequest();

public:
    int https_setup(HTTPS_SETTING &cfg);
    int do_get_request(const std::string &url, const std::list<std::string> &add_headers, HTTPS_RESPONSE &response);
    int do_post_request(const std::string &url, const std::list<std::string> &add_headers, const std::string &body, HTTPS_RESPONSE &response);
    int https_clear();
private:
    int http_init_request(HTTP_CONTEXT *ctx, const std::list<std::string> &add_headers, std::string &req);
    int http_send_request(HTTP_CONTEXT *ctx, const std::string &req, HTTPS_RESPONSE &response);
    int http_write(HTTP_CONTEXT *ctx, const char *buffer, int len);
    int http_read(HTTP_CONTEXT *ctx);
private:
    HTTP_CONTEXT *m_ctx;
};

#endif  //_HTTPS_REQUEST_H_