#include<vector>
#include<string>
#include<array>
#ifndef PROTOCOL_TOOLS_H
#define PROTOCOL_TOOLS_H
// Enum for Operations (Op)
enum class Operation {
    REQ_REGISTER = 600,
    REQ_GETCLIENT_LIST = 601,
    REQ_GETCLIENT_PUBLIC = 602,
    REQ_SENDCLIENT_MESSAGE = 603,
    REQ_PULLMESAGES = 604,
    RESP_SUCSESS_REGISTER = 2100,
    RESP_CLIENT_LIST = 2101,
    RESP_CLIENT_PUBLIC = 2102,
    RESP_MESSAGE_PROCCESED = 2103,
    RESP_PENDINGMESSAGE = 2104,
    RESP_ERROR = 9000
};


// Structure to represent a UUID
struct UUID {
    std::array<uint8_t, 16> id;
};

// Structure to represent a Request
struct Request {
    UUID user_id;
    uint8_t version;
    uint16_t code;
    uint32_t size;
    std::vector<uint8_t> payload;
};

// Structure to represent a Response
struct Response {
    uint8_t version;
    uint16_t code;
    uint32_t size;
    std::vector<uint8_t> payload;
};

Response parse_response(const std::vector<uint8_t>& raw_data);
std::vector<uint8_t> construct_request(const Request& req);

#endif