/*************************************************
 * File name : HttpsResponse.h
 * Introduce : HTTPS/HTTP response class, this class
 *             is a parser for HTTP response header 
 *             and body, support chuncked body.
 * Create: 2021-6-13 by yyf
 * 
 *************************************************/
#ifndef _HTTPS_RESPONSE_H_
#define _HTTPS_RESPONSE_H_

#include <algorithm>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <sstream>

/**
 * @brief Response parse results
 * 
 */
enum ParseResult {
    ParsingCompleted,
    ParsingIncompleted,
    ParsingError
};

/**
 * @brief Response struct, include header items and body
 * 
 */
struct Response {
    Response()
            : versionMajor(0), versionMinor(0), keepAlive(false), statusCode(0) {}

    struct HeaderItem {
        std::string name;
        std::string value;
    };

    int versionMajor;
    int versionMinor;
    std::vector<HeaderItem> headers;
    std::vector<char> content;
    bool keepAlive;

    unsigned int statusCode;
    std::string status;
};

/**
 * @brief Http response parser class
 * 
 */
class HttpsResponse {
private:
    // The current state of the parser.
    enum State {
        ResponseStatusStart,
        ResponseHttpVersion_ht,
        ResponseHttpVersion_htt,
        ResponseHttpVersion_http,
        ResponseHttpVersion_slash,
        ResponseHttpVersion_majorStart,
        ResponseHttpVersion_major,
        ResponseHttpVersion_minorStart,
        ResponseHttpVersion_minor,
        ResponseHttpVersion_statusCodeStart,
        ResponseHttpVersion_statusCode,
        ResponseHttpVersion_statusTextStart,
        ResponseHttpVersion_statusText,
        ResponseHttpVersion_newLine,
        HeaderLineStart,
        HeaderLws,
        HeaderName,
        SpaceBeforeHeaderValue,
        HeaderValue,
        ExpectingNewline_2,
        ExpectingNewline_3,
        Post,
        ChunkSize,
        ChunkExtensionName,
        ChunkExtensionValue,
        ChunkSizeNewLine,
        ChunkSizeNewLine_2,
        ChunkSizeNewLine_3,
        ChunkTrailerName,
        ChunkTrailerValue,

        ChunkDataNewLine_1,
        ChunkDataNewLine_2,
        ChunkData,
    } state;
public:
    HttpsResponse();
    virtual ~HttpsResponse();

public:
    ParseResult parse(Response &resp, const char *begin, const char *end);

private:
    static bool checkIfConnection(const Response::HeaderItem &item);

    ParseResult consume(Response &resp, const char *begin, const char *end);

    // Check if a byte is an HTTP character.
    inline bool isChar(int c);

    // Check if a byte is an HTTP control character.
    inline bool isControl(int c);

    // Check if a byte is defined as an HTTP special character.
    inline bool isSpecial(int c);

    // Check if a byte is a digit.
    inline bool isDigit(int c);

private:
    size_t contentSize;
    std::string chunkSizeStr;
    size_t chunkSize;
    bool chunked;
};

#endif // _HTTPS_RESPONSE_H_
