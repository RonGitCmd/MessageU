#include "protocol_tools.h"
#include "AESWrapper.h"
#include "RSAWrapper.h"
#include <cstring> 
#include <vector>  
#include <string>
#include <iostream>







UUID::UUID(const UUID& other)
{
    id = other.id;
}
UUID::~UUID()
{

}


UUID& UUID::operator=(const UUID& other)
{
    if (this != &other) {
        id = other.id;
    }
    return *this;
}

UUID::UUID()
{}

// Comparison operators (compare the contents of the 'id' array)
bool UUID::operator==(const UUID& other) const
{
    return id == other.id;
    
}

bool UUID::operator!=(const UUID& other) const
{
    return !(*this == other);
}


bool  UUID::operator <(const UUID& other) const
{
    return id < other.id;
    // C++20: std::array has built-in operator< for lexicographic comparison
    // For older compilers, you could use:
    // return std::lexicographical_compare(id.begin(), id.end(),
    //                                     other.id.begin(), other.id.end());
}


// Function to parse a response from raw data
Response parse_response(const std::vector<uint8_t>& raw_data) {
    Response res;
    size_t offset = 0;

    // Extract version
    memcpy(&res.version, &raw_data[offset], sizeof(res.version));
    offset += sizeof(res.version);

    // Extract code
    memcpy(&res.code, &raw_data[offset], sizeof(res.code));
    offset += sizeof(res.code);

    // Extract size
    memcpy(&res.size, &raw_data[offset], sizeof(res.size));
    offset += sizeof(res.size);

    // extract payload
    res.payload = std::vector<uint8_t>(raw_data.begin() + offset, raw_data.end());

    return res;
}

// Function to construct a request into raw data
std::vector<uint8_t> construct_request(const Request& req) {
    std::vector<uint8_t> raw_data(0);


    raw_data.insert(raw_data.end(), req.user_id.id.begin(), req.user_id.id.end());
    raw_data.push_back(req.version);

    

    raw_data.insert(raw_data.end(), reinterpret_cast<const uint8_t*>(&req.code), reinterpret_cast<const uint8_t*>(&req.code) + sizeof(req.code));
    raw_data.insert(raw_data.end(), reinterpret_cast<const uint8_t*>(&req.size), reinterpret_cast<const uint8_t*>(&req.size) + sizeof(req.size));

    if (req.code == (uint16_t)Operation::REQ_GETCLIENT_LIST ||
        req.code == (uint16_t)Operation::REQ_PULLMESAGES
        )
        return raw_data;//Next fields are empty in the REQUEST
   
    raw_data.insert(raw_data.end() , req.payload.begin(), req.payload.end());


    return raw_data;
}


std::map<std::string, UUID> extractClientMap(const std::vector<uint8_t>& data) {
    constexpr size_t recordSize = 271; // 16 bytes for UUID + 255 bytes for username
    if (data.size() % recordSize != 0) {
        throw std::runtime_error("Invalid data size: not a multiple of 271 bytes");
    }

    std::map<std::string, UUID> clientMap;
    size_t numRecords = data.size() / recordSize;

    for (size_t i = 0; i < numRecords; ++i) {
        const uint8_t* recordStart = data.data() + i * recordSize;

        // Extract UUID: first 16 bytes.
        UUID uuid;
        std::copy(recordStart, recordStart + 16, uuid.id.begin());

        // Extract username: next 255 bytes.
        // We treat the username bytes as a C-string, stopping at the first null terminator.
        const char* usernamePtr = reinterpret_cast<const char*>(recordStart + 16);
        std::string username(usernamePtr, 255);
        size_t pos = username.find('\0');
        if (pos != std::string::npos) {
            username.resize(pos);
        }

        // Insert into map (username as key, UUID as value)
        clientMap[username] = uuid;
    }

    return clientMap;
}

/// <summary>
/// parsses all messages in a payload of pull message reply
/// </summary>
/// <param name="payload"></param>
/// <returns></returns>
std::vector<ClientMessage> parseMessages(const std::vector<uint8_t>& payload)
{
    std::vector<ClientMessage> messages;
    size_t index = 0;//cur ind
    const size_t total_size = payload.size();

    while (index < total_size)
    {
        //check if 25 first bytes (uuid m_id m_type m_size)
        if (total_size - index < 25) {
            throw std::runtime_error("insufficient bytes for next message header");
        }

        UUID src_uuid;
        std::memcpy(src_uuid.id.data(), &payload[index], 16);
        index += 16;

     
        uint32_t message_id = 0;
        std::memcpy(&message_id, &payload[index], 4);
        index += 4;

        if (index >= total_size) {
            throw std::runtime_error("insufficient bytes for message type");
        }
        uint8_t msg_type_byte = payload[index++];
        MessageTypes message_type = static_cast<MessageTypes>(msg_type_byte);

        if (index + 4 > total_size) {
            throw std::runtime_error("insufficient bytes for message size");
        }
        uint32_t msg_size = 0;
        std::memcpy(&msg_size, &payload[index], 4);
        index += 4;

        if (index + msg_size > total_size) {
            throw std::runtime_error("insufficient bytes for message content");
        }
        

        // Construct the message and push to vector
        ClientMessage msg;
        msg.source_uuid = src_uuid;
        msg.message_id = message_id;
        msg.message_type = message_type;
        msg.message_size = msg_size;
        msg.content = std::vector<uint8_t>(payload.begin() + index, payload.begin() + index + msg_size);
        index += msg_size;

        messages.push_back(std::move(msg));
    } 

    return messages;
}
