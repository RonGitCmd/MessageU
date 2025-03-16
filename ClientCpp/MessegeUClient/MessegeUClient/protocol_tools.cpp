#include "protocol_tools.h"
#include "AESWrapper.h"
#include "RSAWrapper.h"
#include <cstring> 
#include <vector>  
#include <string>
#include <iostream>
#include <boost/endian/conversion.hpp> 






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

// Convert from 'Request' to a raw byte vector in little-endian
std::vector<uint8_t> construct_request(const Request& req)
{
    std::vector<uint8_t> raw_data;

    // 1) Insert 16 bytes of the UUID (raw data, no endianness conversion for IDs).
    raw_data.insert(raw_data.end(), req.user_id.id.begin(), req.user_id.id.end());

    // 2) Insert the single-byte version as-is (no endianness change).
    raw_data.push_back(req.version);

    // 3) Convert req.code (uint16_t) from native to little-endian, then insert.
    {
        uint16_t code_le = boost::endian::native_to_little(req.code);
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&code_le);
        raw_data.insert(raw_data.end(), ptr, ptr + sizeof(code_le));
    }

    // 4) Convert req.size (uint32_t) from native to little-endian, then insert.
    {
        uint32_t size_le = boost::endian::native_to_little(req.size);
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&size_le);
        raw_data.insert(raw_data.end(), ptr, ptr + sizeof(size_le));
    }

    // 5) If no additional fields, insert the payload as is.
    //    Example: if the request code is REQ_GETCLIENT_LIST or REQ_PULLMESSAGES, maybe skip the payload.
    if (req.code != static_cast<uint16_t>(Operation::REQ_GETCLIENT_LIST)
        && req.code != static_cast<uint16_t>(Operation::REQ_PULLMESAGES))
    {
        raw_data.insert(raw_data.end(), req.payload.begin(), req.payload.end());
    }

    return raw_data;
}

// Convert from a raw byte vector in little-endian to a 'Response'
Response parse_response(const std::vector<uint8_t>& raw_data)
{
    Response res;
    size_t offset = 0;

    // 1) version is 1 byte, copy directly
    if (offset + sizeof(res.version) > raw_data.size())
        throw std::runtime_error("Not enough bytes for version");
    std::memcpy(&res.version, &raw_data[offset], sizeof(res.version));
    offset += sizeof(res.version);

    // 2) code is a 16-bit little-endian
    {
        if (offset + sizeof(res.code) > raw_data.size())
            throw std::runtime_error("Not enough bytes for code");
        uint16_t code_le = 0;
        std::memcpy(&code_le, &raw_data[offset], sizeof(code_le));
        offset += sizeof(code_le);
        res.code = boost::endian::little_to_native(code_le);
    }

    // 3) size is a 32-bit little-endian
    {
        if (offset + sizeof(res.size) > raw_data.size())
            throw std::runtime_error("Not enough bytes for size");
        uint32_t size_le = 0;
        std::memcpy(&size_le, &raw_data[offset], sizeof(size_le));
        offset += sizeof(size_le);
        res.size = boost::endian::little_to_native(size_le);
    }

    // 4) The rest is payload
    if (offset > raw_data.size())
        throw std::runtime_error("Offset out of range after reading header");
    res.payload.insert(res.payload.end(), raw_data.begin() + offset, raw_data.end());

    return res;
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

     
        uint32_t message_id_le = 0;
        std::memcpy(&message_id_le, &payload[index], 4);
        index += 4;
        // Convert from little-endian to host endianness
        message_id_le = boost::endian::little_to_native(message_id_le);

        if (index >= total_size) {
            throw std::runtime_error("insufficient bytes for message type");
        }
        uint8_t msg_type_byte = payload[index++];
        MessageTypes message_type = static_cast<MessageTypes>(msg_type_byte);

        if (index + 4 > total_size) {
            throw std::runtime_error("insufficient bytes for message size");
        }
        uint32_t msg_size_le = 0;
        std::memcpy(&msg_size_le, &payload[index], 4);
        index += 4;
        msg_size_le = boost::endian::little_to_native(msg_size_le);

        if (index + msg_size_le > total_size) {
            throw std::runtime_error("insufficient bytes for message content");
        }
        

        // Construct the message and push to vector
        ClientMessage msg;
        msg.source_uuid = src_uuid;
        msg.message_id = message_id_le;
        msg.message_type = message_type;
        msg.message_size = msg_size_le;
        if (msg_size_le != 0)
            msg.content = std::vector<uint8_t>(payload.begin() + index, payload.begin() + index + msg_size_le);
        else
            msg.content = std::vector<uint8_t>(0);
        index += msg_size_le;

        messages.push_back(std::move(msg));
    } 

    return messages;
}
