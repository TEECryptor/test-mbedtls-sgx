#include "HttpsRequestTask.h"
#include "tee_error.h"
#include "log.h"
#include "https_client.h"
#include "nlohmann/json.hpp"

extern int err_msg_ret(int err_code, const std::string &err_msg, std::string &out);

using JSON = nlohmann::json;
namespace Test {

/**
 * @brief Do a https request, return the response string in JSON
 * 
 * @param step ignore
 * @param request parameter string in JSON, like bellow:
 * {
 *  "url": string, request url path
 *  "certs": string, cert chain string in pem
 *  "method": string, "POST" or "GET"
 *  "req_body": JSON object, request body
 * }
 * @param response result string in JSON
 * @return int 
 */
int HttpsRequestTask::execute(const std::string &request, std::string &response )
{
    int ret = 0;
    std::string url;
    std::string certs;
    std::string method;
    std::string req_body;
    std::string res_body;
    std::list<std::string> header_arr;
    JSON headers;
    JSON root;

    FUNC_BEGIN;

    try {
        root = JSON::parse(request);
        url = root["url"];
        certs = root["certs"];
        method = root["method"];
        headers = root["headers"];
        for (JSON::iterator it = headers.begin(); it != headers.end(); ++it) {
            //std::string key = it.key();
            //std::string value = it.value();
            //std::string header = key + ": " + value;
            header_arr.push_back(*it);
        }
        req_body = !root["req_body"].is_null() ? root["req_body"] : "";

        if ((ret = do_https_request(url, certs, method, header_arr, req_body, res_body)) != 0) {
            ERROR("do_https_request() failed! ret: %d", ret);
            return err_msg_ret(TEE_ERROR_INVALID_PARAM, "do_https_request() failed!", response);
        }

        response = res_body;
    }
    catch (JSON::exception& e) {
        ERROR("Invalid json! input: %s, error: %s", request.c_str(), e.what());
        return err_msg_ret(TEE_ERROR_INVALID_PARAM, "Invalid json!", response);
    }

    FUNC_END;

    return ret;
}

uint32_t HttpsRequestTask::get_task_type( )
{
    return TEST_HTTPS_REQUEST_TASK;
}

int HttpsRequestTask::do_https_request(const std::string &url, const std::string &ca_certs, 
        const std::string &method, const std::list<std::string> &headers, 
        const std::string &req_body, std::string &res_body)
{
    int ret = 0;
    HTTPS_SETTING http_cfg;
    HTTPS_RESPONSE http_resp;
    IHttpsRequest *http_req = nullptr;

    FUNC_BEGIN;

    if (url.length() == 0) {
        ERROR("url is null!");
        return TEE_ERROR_INVALID_PARAM;
    }

    // http request setting
    http_cfg.is_https = ca_certs.length() > 0 ? true : false;
    http_cfg.verify_host = true;
    http_cfg.ca_crt = ca_certs;

    // create http request object
    if (!(http_req = HttpsRequest_Create())) {
        ERROR("HttpsRequest_Create() failed!");
        ret = TEE_ERROR_INTERNAL_ERROR;
        goto exit;
    }
    if ((ret = http_req->https_setup(http_cfg)) != 0) {
        ERROR("http_req->https_setup() failed! ret: %d", ret);
        ret = TEE_ERROR_INTERNAL_ERROR;
        goto exit;
    }

    if (method == "GET") {
        ret = http_req->do_get_request(url, headers, http_resp);
    }
    else if (method == "POST") {
        ret = http_req->do_post_request(url, headers, req_body, http_resp);
    }
    else {
        ERROR("method is wrong! method: %s", method.c_str());
        ret = TEE_ERROR_INVALID_PARAM;
        goto exit;
    }
    if ((ret != TEE_OK)) {
        ERROR("HTTP request failed! ret: %d", ret);
        ret = TEE_ERROR_INTERNAL_ERROR;
        goto exit;
    }
    if (!http_resp.success || 200 != http_resp.status) {
        ERROR("HTTP request failed with an unsuccess status!");
        ERROR("--->resp status: %d", http_resp.status);
        ERROR("--->resp body: %s", http_resp.body.c_str());
        ret = TEE_ERROR_INTERNAL_ERROR;
        goto exit;
    }

    // Success
    res_body = http_resp.body;

    FUNC_END;
exit:
    if (http_req) {
        HttpsRequest_Destory(http_req);
        http_req = nullptr;
    }
    return ret;
}
}