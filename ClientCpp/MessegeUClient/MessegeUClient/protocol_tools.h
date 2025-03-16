#include<vector>
#include<string>
#include<array>
#include<map>
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


enum class MessageTypes {
    REQ_SYM = 1,
    SEND_SYM = 2,
    SEND_TEXT_MESSAGE = 3,
    SEND_FILE = 4
};

// class to represent a UUID
class UUID {
public:
    std::array<uint8_t, 16> id;
    ~UUID();
    

    UUID(const UUID& other);
    

    UUID& operator=(const UUID& other);
   
    UUID();
  
    // Comparison operators (compare the contents of the 'id' array)
    bool operator==(const UUID& other) const;
    

    bool operator!=(const UUID& other) const;
    bool  operator <(const UUID& other) const;
   
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

struct ClientMessage {
    UUID source_uuid;
    uint32_t message_id;
    MessageTypes message_type;
    uint32_t message_size;
    std::vector<uint8_t> content;
};

Response parse_response(const std::vector<uint8_t>& raw_data);
std::vector<uint8_t> construct_request(const Request& req);
std::map<std::string, UUID> extractClientMap(const std::vector<uint8_t>& data);
std::vector<ClientMessage> parseMessages(const std::vector<uint8_t>& payload);


#endif