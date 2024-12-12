/*************************************************
 * File name : HttpsRequest.cpp
* Introduce : HTTPS/HTTP request class, this class
 *            use library mbedtls to do a HTTPS/HTTP
 *            request.
 * Create: 2021-6-9 by yyf
 * 
 *************************************************/
#include <unistd.h>
#include <mbedtls/platform.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include "https_request.h"
#include "https_response.h"
#include "log.h"

/*
 * Initiate a TCP connection with host:port and the given protocol
 * waiting for timeout (ms)
 */
static int mbedtls_net_connect_timeout(mbedtls_net_context *ctx,
                                       std::string host,
                                       std::string port,
                                       int proto,
                                       uint32_t timeout);

/*
 * mbedtls debug information callback function 
 */
static void mbedtls_debug(void *ctx,
                          int level,
                          const char *file,
                          int line,
                          const char *str) {
    ERROR("mbedtls_debug ====> %s:%04d: %s", file, line, str);
}
/******************************************
 * Name:HttpsRequest
 * Introduce:construction function 
 * Params:N/A
 * Return:N/A
 ******************************************/
HttpsRequest::HttpsRequest()
        : m_ctx(nullptr) {

}
/******************************************
 * Name:~HttpsRequest
 * Introduce:distruction function 
 * Params:N/A
 * Return:N/A
 ******************************************/
HttpsRequest::~HttpsRequest() {
    if (m_ctx) {
        https_clear();
    }
}

/******************************************
 * Name:https_setup
 * Introduce:Initialize a http context, this function should be called at first. 
 * Params:header:[IN]: HTTP request header settings
 *        ca_crt:[IN]: if is_https is true, ca_crt is the ca certifcates chain string, in PEM
 * Return:return 0 if successful, otherwise return an error code.
 ******************************************/
int HttpsRequest::https_setup(HTTPS_SETTING &cfg) {
    int ret = 0;
    char tmp[512] = {0};

    // re-new context object
    if (m_ctx) {
        https_clear();
    }
    m_ctx = new HTTP_CONTEXT;
    if (!m_ctx) {
        ERROR("new HTTP_CONTEXT return null!");
        return HTTPS_ERR_FAILED_TO_MALLOC;
    }

    // save global configure
    m_ctx->cfg.is_https = cfg.is_https;
    m_ctx->cfg.verify_host = cfg.verify_host;
    m_ctx->cfg.time_out = cfg.time_out;
    m_ctx->cfg.content_type = cfg.content_type;
    m_ctx->cfg.connection = cfg.connection;
    m_ctx->cfg.authorization = cfg.authorization;
    m_ctx->cfg.ca_crt = cfg.ca_crt;

    // base setup
    mbedtls_net_init_ocall(&m_ctx->tls.ssl_fd);

    // setup for https
    if (m_ctx->cfg.is_https) {
        mbedtls_ssl_init(&m_ctx->tls.ssl);
        mbedtls_ssl_config_init(&m_ctx->tls.conf);
        mbedtls_x509_crt_init(&m_ctx->tls.ca_cert);
        mbedtls_ctr_drbg_init(&m_ctx->tls.ctr_drbg);
        mbedtls_entropy_init(&m_ctx->tls.entropy);
        if ((ret = mbedtls_ctr_drbg_seed(&m_ctx->tls.ctr_drbg,
                                         mbedtls_entropy_func,
                                         &m_ctx->tls.entropy,
                                         (const unsigned char *) SEED_PERS,
                                         strlen(SEED_PERS))) != 0) {
            mbedtls_strerror(ret, tmp, sizeof(tmp));
            ERROR("mbedtls_ctr_drbg_seed() failed! ret: -0x%04x", -ret);
            ERROR("--->err_msg: %s", tmp);
            ret = HTTPS_ERR_MBEDTLS_SEED_FAILED;
            goto exit;
        }
        if (m_ctx->cfg.ca_crt.length() > 0) {
            if ((ret = mbedtls_x509_crt_parse(&m_ctx->tls.ca_cert,
                                              (const unsigned char *) m_ctx->cfg.ca_crt.c_str(),
                                              m_ctx->cfg.ca_crt.length() + 1)) != 0) {
                mbedtls_strerror(ret, tmp, sizeof(tmp));
                ERROR("mbedtls_x509_crt_parse() failed! ret: -0x%04x", -ret);
                ERROR("--->err_msg: %s", tmp);
                ret = HTTPS_ERR_MBEDTLS_CACERT_WRONG;
                goto exit;
            }
        }
        if ((ret = mbedtls_ssl_config_defaults(&m_ctx->tls.conf,
                                               MBEDTLS_SSL_IS_CLIENT,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            mbedtls_strerror(ret, tmp, sizeof(tmp));
            ERROR("mbedtls_ssl_config_defaults() failed! ret: -0x%04x", -ret);
            ERROR("--->err_msg: %s", tmp);
            ret = HTTPS_ERR_MBEDTLS_CONFIG_FAILED;
            goto exit;
        }

        // other settings
        mbedtls_ssl_conf_authmode(&m_ctx->tls.conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&m_ctx->tls.conf, &m_ctx->tls.ca_cert, NULL);
        mbedtls_ssl_conf_rng(&m_ctx->tls.conf, mbedtls_ctr_drbg_random, &m_ctx->tls.ctr_drbg);
        mbedtls_ssl_conf_dbg(&m_ctx->tls.conf, mbedtls_debug, nullptr);
        mbedtls_ssl_conf_read_timeout(&m_ctx->tls.conf, m_ctx->cfg.time_out);
    }

    // return ok
    return HTTPS_ERR_OK;

    exit:
    // failed, clear
    https_clear();
    return ret;
}
/******************************************
 * Name:do_get_request
 * Introduce:Send a GET request to url
 * Params:url:[IN]: full url for service address, like "https://www.baidu.com/login/#xxxxx?xxxxx"
 *        response:[OUT]: respose data for this requesting
 * Return:return 0 if successful, otherwise return an error code.
 ******************************************/
int HttpsRequest::do_get_request(const std::string &url, 
                                 const std::list<std::string> &add_headers,
                                 HTTPS_RESPONSE &response) {
    int ret = 0;
    int req_len = 0;
    std::string req;

    // check m_ctx
    if (!m_ctx) {
        ERROR("m_ctx is null!");
        return HTTPS_ERR_INVALIDCALL;
    }

    // check input
    if (url.length() <= 0) {
        ERROR("url is null!");
        return HTTPS_ERR_INVALIDPARAM;
    }

    // copy request to m_ctx
    m_ctx->resquest.method = "GET";
    m_ctx->resquest.url.parse(url);

    //INFO( "[DEBUG] url : %s ", url.c_str() );
    //INFO( "[DEBUG] host : %s, port : %s",
    //         m_ctx->resquest.url.hostname().c_str(),
    //         m_ctx->resquest.url.port().c_str() );

    // check scheme is same as setting or not
    if ((m_ctx->cfg.is_https && m_ctx->resquest.url.scheme() != "https") ||
            (!m_ctx->cfg.is_https && m_ctx->resquest.url.scheme() != "http")) {
        ERROR("url's scheme is not same as setup! m_ctx->cfg.is_https: %d", m_ctx->cfg.is_https);
        return HTTPS_ERR_URLSCHEME_WRONG;
    }

    // construct request string
    if ((ret = http_init_request(m_ctx, add_headers, req)) != 0) {
        ERROR("http_init_request() failed! ret: %d", ret);
        return ret;
    }

    // send request
    if ((ret = http_send_request(m_ctx, req, response)) != 0) {
        ERROR("http_send_request() failed! ret: %d", ret);
        return ret;
    }

    return HTTPS_ERR_OK;
}
/******************************************
 * Name:do_post_request
 * Introduce:Send a POST request to url
 * Params:url:[IN]: full url for service address, like "https://www.baidu.com/login"
 *        body:[IN]: POST request body string
 *        response:[OUT]: respose data for this requesting
 * Return:return 0 if successful, otherwise return an error code.
 ******************************************/
int HttpsRequest::do_post_request(const std::string &url,
                                  const std::list<std::string> &add_headers,
                                  const std::string &body,
                                  HTTPS_RESPONSE &response) {
    int ret = 0;
    std::string req;
    int req_len = 0;

    // check m_ctx
    if (!m_ctx) {
        ERROR("m_ctx is null!");
        return HTTPS_ERR_INVALIDPARAM;
    }

    // check input
    if (url.length() <= 0) {
        ERROR("ulr is null!");
        return HTTPS_ERR_INVALIDPARAM;
    }

    // copy request to m_ctx
    m_ctx->resquest.method = "POST";
    m_ctx->resquest.body = body;
    m_ctx->resquest.url.parse(url);

    //INFO( "[DEBUG] url : %s ", url.c_str() );
    //INFO( "[DEBUG] host : %s, port : %s",
    //       m_ctx->resquest.url.hostname().c_str(),
    //       m_ctx->resquest.url.port().c_str() );

    // check scheme is same as setting or not
    if ((m_ctx->cfg.is_https && m_ctx->resquest.url.scheme() != "https") ||
            (!m_ctx->cfg.is_https && m_ctx->resquest.url.scheme() != "http")) {
        ERROR("url's scheme is not same in setup! m_ctx->cfg.is_https: %d", m_ctx->cfg.is_https);
        return HTTPS_ERR_INVALIDPARAM;
    }

    // construct request string
    if ((ret = http_init_request(m_ctx, add_headers, req)) != 0) {
        ERROR("http_init_request() failed! ret: %d", ret);
        return ret;
    }

    // send request
    if ((ret = http_send_request(m_ctx, req, response)) != 0) {
        ERROR("http_send_request() failed! ret: %d", ret);
        return ret;
    }

    return HTTPS_ERR_OK;
}
/******************************************
 * Name:https_clear
 * Introduce:Release current http context object
 * Return:return 0 if successful, otherwise return an error code.
 ******************************************/
int HttpsRequest::https_clear() {
    if (m_ctx) {
        if (m_ctx->cfg.is_https) {
            mbedtls_ssl_close_notify(&m_ctx->tls.ssl);
        }

        mbedtls_net_free_ocall(&m_ctx->tls.ssl_fd);

        if (m_ctx->cfg.is_https) {
            mbedtls_x509_crt_free(&m_ctx->tls.ca_cert);
            mbedtls_ssl_free(&m_ctx->tls.ssl);
            mbedtls_ssl_config_free(&m_ctx->tls.conf);
            mbedtls_ctr_drbg_free(&m_ctx->tls.ctr_drbg);
            mbedtls_entropy_free(&m_ctx->tls.entropy);
        }

        delete m_ctx;
        m_ctx = nullptr;
    }

    return 0;
}

// construct request string
int HttpsRequest::http_init_request(HTTP_CONTEXT *ctx, const std::list<std::string> &add_headers, std::string &req) {
    // check ctx
    if (!ctx) {
        ERROR("ctx is null in http_get_request()");
        return HTTPS_ERR_INVALIDCALL;
    }

    // method
    req.append(ctx->resquest.method);
    req.append(" ");
    // path
    req.append(ctx->resquest.url.path());
    if (ctx->resquest.url.query().length() > 0) {
        req.append("?");
        req.append(ctx->resquest.url.query());
    }
    req.append(" ");
    // version
    req.append("HTTP/1.1\r\n");
    // User-Agent
    req.append("User-Agent: Mozilla/4.0\r\n");
    // Host and port
    req.append("Host: ");
    req.append(ctx->resquest.url.hostname());
    req.append(":");
    req.append(ctx->resquest.url.port());
    req.append("\r\n");
    // Accept
    req.append("Accept: */*\r\n");
    // Transaction
    req.append("Transaction: ");
    req.append(ctx->cfg.connection.length() > 0 ? ctx->cfg.connection : "Keep-Alive");
    req.append("\r\n");
    // Content-Type
    //req.append("Content-Type: ");
    //req.append(ctx->cfg.content_type.length() > 0 ? ctx->cfg.content_type : "application/JSON; charset=utf-8");
    //req.append("\r\n");
    // Authorization
    req.append("Authorization: ");
    req.append(ctx->cfg.authorization.length() > 0 ? ctx->cfg.authorization : "");
    req.append("\r\n");
    //
    req.append("Access-Control-Allow-Origin: *");
    req.append("\r\n");
    // Content-Length
    if (ctx->resquest.method == "POST") {
        req.append("Content-Length: ");
        req.append(std::to_string(ctx->resquest.body.length()));
        req.append("\r\n");
    }

    // customized headers
    for(std::string item : add_headers) {
        req.append(item);
        req.append("\r\n");
    }

    // cookie
    req.append("");
    req.append("\r\n");

    // body
    if (ctx->resquest.method == "POST") {
        req.append(ctx->resquest.body);
    }

    //ERROR( "--->[DEBUG]req:\r\n %s \r\n", req.c_str() );
//    INFO("Req: %s\n", req.c_str());

    return HTTPS_ERR_OK;
}

// send the request and receice response
int HttpsRequest::http_send_request(HTTP_CONTEXT *ctx, const std::string &req, HTTPS_RESPONSE &response) {
    int ret = 0;
    int req_len = 0;
    char err_msg[512] = {0};

    // check m_ctx
    if (!ctx) {
        ERROR("ctx is null in http_send_request()");
        return HTTPS_ERR_INVALIDCALL;
    }

    // check input
    if (req.length() <= 0) {
        ERROR("req is null in http_send_request()");
        return HTTPS_ERR_INVALIDPARAM;
    }
/*
    //  set time out
    if ( ( ret = mbedtls_net_connect_timeout( &ctx->tls.ssl_fd, 
                                              ctx->resquest.url.hostname(), 
                                              ctx->resquest.url.port(), 
                                              MBEDTLS_NET_PROTO_TCP, 
                                              ctx->cfg.time_out ) ) != 0 ) {
        //fprintf( stderr, "[ERROR] mbedtls_net_connect_timeout() failed! ret = %d\n", ret );
        return HTTPS_ERR_MBEDTLS_SET_TIEMOUT_FAILED;
    }
*/

    // connect without timeout
    if ((ret = mbedtls_net_connect_ocall(&ctx->tls.ssl_fd,
                                         ctx->resquest.url.hostname().c_str(),
                                         ctx->resquest.url.port().c_str(),
                                         MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_strerror(ret, err_msg, sizeof(err_msg));
        ERROR("mbedtls_net_connect() failed! ret: -0x%04x", -ret);
        ERROR("--->host:%s, port: %s", ctx->resquest.url.hostname().c_str(), ctx->resquest.url.port().c_str());
        ERROR("--->err_msg: %s", err_msg);
        ret = HTTPS_ERR_MBEDTLS_CONNECT_FAILED;
        goto exit;
    }

    // for https shake hand
    if (ctx->cfg.is_https) {
        if ((ret = mbedtls_ssl_setup(&ctx->tls.ssl, &ctx->tls.conf)) != 0) {
            mbedtls_strerror(ret, err_msg, sizeof(err_msg));
            ERROR("mbedtls_ssl_setup() failed! ret: -0x%04x", -ret);
            ERROR("--->err_msg: %s", err_msg);
            ret = HTTPS_ERR_MBEDTLS_SSL_SETUP_FAILED;
            goto exit;
        }

        if ((ret = mbedtls_ssl_set_hostname(&ctx->tls.ssl, ctx->resquest.url.hostname().c_str())) != 0) {
            mbedtls_strerror(ret, err_msg, sizeof(err_msg));
            ERROR("mbedtls_ssl_set_hostname() failed! ret: -0x%04x", -ret);
            ERROR("--->err_msg: %s", err_msg);
            ret = HTTPS_ERR_MBEDTLS_SSL_HOST_FAILED;
            goto exit;
        }
        mbedtls_ssl_set_bio(&ctx->tls.ssl, &ctx->tls.ssl_fd, mbedtls_net_send_ocall,
                            mbedtls_net_recv_ocall, mbedtls_net_recv_timeout_ocall);

        while ((ret = mbedtls_ssl_handshake(&ctx->tls.ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                ERROR("mbedtls_ssl_handshake() failed! ret: -0x%04x", -ret);
                ret = HTTPS_ERR_MBEDTLS_HANDSHAKE_FAILED;
                goto exit;
            } else {
                INFO("mbedtls_ssl_handshake() return ret: -0x%04x", -ret);
            }
        }

        /* In real life, we probably want to bail out when ret != 0 */
        if (ctx->cfg.verify_host && ((ret = mbedtls_ssl_get_verify_result(&ctx->tls.ssl)) != 0)) {
            mbedtls_x509_crt_verify_info(err_msg, sizeof(err_msg), "", ret);
            ERROR("mbedtls_ssl_get_verify_result() failed! verify_result: %d", ret);
            ERROR("--->err_msg: %s", err_msg);
            ret = HTTPS_ERR_MBEDTLS_CERT_VERIFY_FAILED;
            goto exit;
        }
    }

    // send the request
    req_len = req.length();
    if ((ret = http_write(ctx, req.c_str(), req_len)) != req_len) {
        mbedtls_strerror(ret, err_msg, sizeof(err_msg));
        ERROR("http_write() failed! ret: -0x%04x", -ret);
        ERROR("--->err_msg: %s", err_msg);
        response.success = false;
        response.body = err_msg;
        ret = HTTPS_ERR_MBEDTLS_WRITE_FAILED;
        goto exit;
    }
    //ERROR( "req:\r\n %s \r\n", req.c_str() );

    // read response
    ctx->response.body.clear();
    if ((ret = http_read(ctx)) <= 0) {
        mbedtls_strerror(ret, err_msg, sizeof(err_msg));
        ERROR("http_read() failed! ret: -0x%04x", -ret);
        ERROR("--->err_msg: %s", err_msg);
        response.success = false;
        response.body = err_msg;
        ret = HTTPS_ERR_MBEDTLS_READ_FAILED;
        goto exit;
    }
    //ERROR( "resp:\r\n %s \r\n", ctx->response.body.c_str() );

    response.success = true;
    response.status = ctx->response.header.status;
    response.body = ctx->response.body;

    ret = HTTPS_ERR_OK;

    exit:
    // disconnet and free socket
    if (ctx->cfg.is_https) {
        mbedtls_ssl_free(&ctx->tls.ssl);
    }
    mbedtls_net_free_ocall(&ctx->tls.ssl_fd);

    return ret;
}

// write data in the connection
int HttpsRequest::http_write(HTTP_CONTEXT *ctx, const char *buffer, int len) {
    int ret = 0;
    int slen = 0;

    if (!ctx || !buffer || len <= 0) {
        return 0;
    }

    while (1) {
        if (ctx->cfg.is_https)
            ret = mbedtls_ssl_write(&ctx->tls.ssl, (u_char *) &buffer[slen], len - slen);
        else
            ret = mbedtls_net_send_ocall(&ctx->tls.ssl_fd, (u_char *) &buffer[slen], len - slen);

        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        else if (ret <= 0) return ret;

        slen += ret;

        if (slen >= len) break;
    }

    return slen;
}

// read data in the connection
int HttpsRequest::http_read(HTTP_CONTEXT *ctx) {
    int ret = 0;
    int read_size = 0;
    unsigned char read_buf[DATA_BUF_SIZE] = {0};
    HttpsResponse resp_parser;
    Response response;
    ParseResult result;

    if (!ctx) {
        return -1;
    }

    while (1) {
        memset(read_buf, 0, DATA_BUF_SIZE);

        if (ctx->cfg.is_https) {
            ret = mbedtls_ssl_read(&ctx->tls.ssl, read_buf, DATA_BUF_SIZE);
        } else {
            ret = mbedtls_net_recv_timeout_ocall(&ctx->tls.ssl_fd, read_buf, DATA_BUF_SIZE, ctx->cfg.time_out);
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
        else if (ret < 0) return ret;
        if (ret == 0) break;

        // got an error data size
        if (ret > DATA_BUF_SIZE) {
            ERROR("mbedtls_ssl_read()/mbedtls_net_recv_timeout_ocall() read data size is wrong! size: %d", ret);
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        read_size += ret;

        result = resp_parser.parse(response, (const char *) read_buf, (const char *) (read_buf + ret));
        if (ParsingCompleted == result ||
                ParsingError == result) {
            break;
        }
    }

    ctx->response.header.status = response.statusCode;
    ctx->response.header.keepAlive = response.keepAlive;
    ctx->response.body.append(response.content.begin(), response.content.end());

    return read_size;
}
/*
 * Initiate a TCP connection with host:port and the given protocol
 * waiting for timeout (ms)
 */
#if 0
static int mbedtls_net_connect_timeout( mbedtls_net_context *ctx, 
                                        std::string host, 
                                        std::string port,
                                        int proto, 
                                        uint32_t timeout )
{
    int ret;
    struct addrinfo hints, *addr_list, *cur;

    signal( SIGPIPE, SIG_IGN );

    /* Do name resolution with both IPv6 and IPv4 */
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if( getaddrinfo( host.c_str(), port.c_str(), &hints, &addr_list ) != 0 )
        return( MBEDTLS_ERR_NET_UNKNOWN_HOST );

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for( cur = addr_list; cur != NULL; cur = cur->ai_next )
    {
        ctx->fd = (int) socket( cur->ai_family, cur->ai_socktype,
                                cur->ai_protocol );
        if( ctx->fd < 0 )
        {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if( mbedtls_net_set_nonblock( ctx ) < 0 )
        {
            close( ctx->fd );
            ctx->fd = -1;
            ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
            break;
        }

        if( connect( ctx->fd, cur->ai_addr, cur->ai_addrlen ) == 0 )
        {
            ret = 0;
            break;
        }
        else if( errno == EINPROGRESS )
        {
            int            fd = (int)ctx->fd;
            int            opt;
            socklen_t      slen;
            struct timeval tv;
            fd_set         fds;

            while(1)
            {
                FD_ZERO( &fds );
                FD_SET( fd, &fds );

                tv.tv_sec  = timeout / 1000;
                tv.tv_usec = ( timeout % 1000 ) * 1000;

                ret = select( fd+1, NULL, &fds, NULL, timeout == 0 ? NULL : &tv );
                if( ret == -1 )
                {
                    if(errno == EINTR) continue;
                }
                else if( ret == 0 )
                {
                    close( fd );
                    ctx->fd = -1;
                    ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
                }
                else
                {
                    ret = 0;

                    slen = sizeof(int);
                    if( (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&opt, &slen) == 0) && (opt > 0) )
                    {
                        close( fd );
                        ctx->fd = -1;
                        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
                    }
                }

                break;
            }

            break;
        }

        close( ctx->fd );
        ctx->fd = -1;
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo( addr_list );

    if( (ret == 0) && (mbedtls_net_set_block( ctx ) < 0) )
    {
        close( ctx->fd );
        ctx->fd = -1;
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    return( ret );
}
#endif //0