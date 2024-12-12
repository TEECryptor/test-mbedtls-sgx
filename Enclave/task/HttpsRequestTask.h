#ifndef TEST_HTTPS_REQUEST_TASK_H
#define TEST_HTTPS_REQUEST_TASK_H

#include "Task.h"
#include <list>

namespace Test {

class HttpsRequestTask: public Task
{
public:
    virtual int execute(const std::string &request, std::string &response );
    virtual uint32_t get_task_type( );
private:
    int do_https_request(const std::string &url, const std::string &ca_certs, const std::string &method, const std::list<std::string> &headers, const std::string &req_body, std::string &res_body);
};

}

#endif //TEST_HTTPS_REQUEST_TASK_H