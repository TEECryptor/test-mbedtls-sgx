/*************************************************
 * File name : HttpsUrl.h
 * Introduce : Implement file for http(s) url parser class.
 * 
 * Create: 2021-6-10 by yyf
 * 
 *************************************************/
#include <string>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "https_url.h"

HttpsUrl::HttpsUrl()
        : valid(false) {
}
HttpsUrl::HttpsUrl(const std::string &url)
        : valid(true) {
    parse(url);
}

HttpsUrl::~HttpsUrl() {

}

bool HttpsUrl::parse(const std::string &str) {
    url = Url();
    parse_(str);

    return isValid();
}

bool HttpsUrl::isValid() const {
    return valid;
}

std::string HttpsUrl::scheme() const {
    assert(isValid());
    return url.scheme;
}

std::string HttpsUrl::username() const {
    assert(isValid());
    return url.username;
}

std::string HttpsUrl::password() const {
    assert(isValid());
    return url.password;
}

std::string HttpsUrl::hostname() const {
    assert(isValid());
    return url.hostname;
}

std::string HttpsUrl::port() const {
    assert(isValid());
    return std::to_string(httpPort());
}

std::string HttpsUrl::path() const {
    assert(isValid());
    return url.path;
}

std::string HttpsUrl::query() const {
    assert(isValid());
    return url.query;
}

std::string HttpsUrl::fragment() const {
    assert(isValid());
    return url.fragment;
}

uint16_t HttpsUrl::httpPort() const {
    const uint16_t defaultHttpPort = 80;
    const uint16_t defaultHttpsPort = 443;

    assert(isValid());

    if (url.port.empty()) {
        if (scheme() == "https")
            return defaultHttpsPort;
        else
            return defaultHttpPort;
    } else {
        return url.integerPort;
    }
}

bool HttpsUrl::isUnreserved(char ch) const {
    if (isalnum(ch))
        return true;

    switch (ch) {
        case '-':
        case '.':
        case '_':
        case '~':return true;
    }

    return false;
}

void HttpsUrl::parse_(const std::string &str) {
    enum {
        Scheme,
        SlashAfterScheme1,
        SlashAfterScheme2,
        UsernameOrHostname,
        Password,
        Hostname,
        IPV6Hostname,
        PortOrPassword,
        Port,
        Path,
        Query,
        Fragment
    } state = Scheme;

    std::string usernameOrHostname;
    std::string portOrPassword;

    valid = true;
    url.path = "/";
    url.integerPort = 0;

    for (size_t i = 0; i < str.size() && valid; ++i) {
        char ch = str[i];

        switch (state) {
            case Scheme:
                if (isalnum(ch) || ch == '+' || ch == '-' || ch == '.') {
                    url.scheme += ch;
                } else if (ch == ':') {
                    state = SlashAfterScheme1;
                } else {
                    valid = false;
                    url = Url();
                }
                break;
            case SlashAfterScheme1:
                if (ch == '/') {
                    state = SlashAfterScheme2;
                } else if (isalnum(ch)) {
                    usernameOrHostname = ch;
                    state = UsernameOrHostname;
                } else {
                    valid = false;
                    url = Url();
                }
                break;
            case SlashAfterScheme2:
                if (ch == '/') {
                    state = UsernameOrHostname;
                } else {
                    valid = false;
                    url = Url();
                }
                break;
            case UsernameOrHostname:
                if (isUnreserved(ch) || ch == '%') {
                    usernameOrHostname += ch;
                } else if (ch == ':') {
                    state = PortOrPassword;
                } else if (ch == '@') {
                    state = Hostname;
                    std::swap(url.username, usernameOrHostname);
                } else if (ch == '/') {
                    state = Path;
                    std::swap(url.hostname, usernameOrHostname);
                } else {
                    valid = false;
                    url = Url();
                }
                break;
            case Password:
                if (isalnum(ch) || ch == '%') {
                    url.password += ch;
                } else if (ch == '@') {
                    state = Hostname;
                } else {
                    valid = false;
                    url = Url();
                }
                break;
            case Hostname:
                if (ch == '[' && url.hostname.empty()) {
                    state = IPV6Hostname;
                } else if (isUnreserved(ch) || ch == '%') {
                    url.hostname += ch;
                } else if (ch == ':') {
                    state = Port;
                } else if (ch == '/') {
                    state = Path;
                } else {
                    valid = false;
                    url = Url();
                }
                break;
            case IPV6Hostname:abort();
            case PortOrPassword:
                if (isdigit(ch)) {
                    portOrPassword += ch;
                } else if (ch == '/') {
                    std::swap(url.hostname, usernameOrHostname);
                    std::swap(url.port, portOrPassword);
                    url.integerPort = atoi(url.port.c_str());
                    state = Path;
                } else if (isalnum(ch) || ch == '%') {
                    std::swap(url.username, usernameOrHostname);
                    std::swap(url.password, portOrPassword);
                    url.password += ch;
                    state = Password;
                } else {
                    valid = false;
                    url = Url();
                }
                break;
            case Port:
                if (isdigit(ch)) {
                    portOrPassword += ch;
                } else if (ch == '/') {
                    std::swap(url.port, portOrPassword);
                    url.integerPort = atoi(url.port.c_str());
                    state = Path;
                } else {
                    valid = false;
                    url = Url();
                }
                break;
            case Path:
                if (ch == '#') {
                    state = Fragment;
                } else if (ch == '?') {
                    state = Query;
                } else {
                    url.path += ch;
                }
                break;
            case Query:
                if (ch == '#') {
                    state = Fragment;
                } else if (ch == '?') {
                    state = Query;
                } else {
                    url.query += ch;
                }
                break;
            case Fragment:url.fragment += ch;
                break;
        }
    }

    assert(portOrPassword.empty());

    if (!usernameOrHostname.empty())
        url.hostname = usernameOrHostname;
}
