#include "protocol_tools.h"
#include <cstring> // For memcpy
#include <vector>  // For dynamic payload handling
#include <string>


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
    std::vector<uint8_t> raw_data;


    raw_data.insert(raw_data.end(), req.user_id.id.begin(), req.user_id.id.end());
    raw_data.push_back(req.version);

    // Add status
    uint16_t code = req.code;
    raw_data.insert(raw_data.end(), reinterpret_cast<uint8_t*>(req.size), reinterpret_cast<uint8_t*>(req.size) + sizeof(req.size));

    raw_data.insert(raw_data.end(), reinterpret_cast<uint8_t*>(&code), reinterpret_cast<uint8_t*>(&code) + sizeof(req.code));
    if (req.code == (uint16_t)Operation::REQ_GETCLIENT_LIST ||
        req.code == (uint16_t)Operation::REQ_PULLMESAGES
        )
        return raw_data;//Next fields are empty in the REQUEST
   
    raw_data.insert(raw_data.end() , req.payload.begin(), req.payload.end());


    return raw_data;
}




