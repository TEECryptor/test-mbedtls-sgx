/*************************************************
 * File name : HttpsClient.cpp
 * Introduce : This library export funcitons implement file
 * 
 * Create: 2021-6-10 by yyf
 * 
 *************************************************/
#include "https_request.h"

/**
 * @brief To create a https request object
 * 
 * @return IHttpsRequest* 
 */
IHttpsRequest *HttpsRequest_Create() {
    HttpsRequest *req = new HttpsRequest();

    return (IHttpsRequest *) req;
}

/**
 * @brief To release a https request object 
 *        which reated by HttpsRequest_Create()
 * 
 * @param req : the object created by HttpsRequest_Create( )
 */
void HttpsRequest_Destory(IHttpsRequest *req) {
    HttpsRequest *request = (HttpsRequest *) req;
    if (request) {
        delete request;
        request = nullptr;
    }
}