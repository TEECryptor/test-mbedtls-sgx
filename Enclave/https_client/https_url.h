/*************************************************
 * File name : HttpsUrl.h
 * Introduce : Header file for http(s) url parser class.
 * 
 * Create: 2021-6-10 by yyf
 * 
 *************************************************/

#ifndef _HTTPS_PARSER_H_
#define _HTTPS_PARSER_H_

#include <string>

/**
 * @brief A class for parsing http(s) url
 * 
 */
class HttpsUrl {
private:
    struct Url {
        Url() : integerPort(0) {}

        std::string scheme;
        std::string username;
        std::string password;
        std::string hostname;
        std::string port;
        std::string path;
        std::string query;
        std::string fragment;
        uint16_t integerPort;
    } url;

public:
    HttpsUrl();
    explicit HttpsUrl(const std::string &url);
    virtual ~HttpsUrl();

public:
    bool parse(const std::string &str);
    bool isValid() const;
    std::string scheme() const;
    std::string username() const;
    std::string password() const;
    std::string hostname() const;
    std::string port() const;
    std::string path() const;
    std::string query() const;
    std::string fragment() const;
    uint16_t httpPort() const;

private:
    bool isUnreserved(char ch) const;
    void parse_(const std::string &str);

private:
    bool valid;
};

#endif // _HTTPS_PARSER_H_
