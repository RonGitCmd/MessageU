#include <cryptopp/cryptlib.h>
#include <boost/asio.hpp>
#include <filesystem>
#include <fstream>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include "protocol_tools.h"



namespace fs = std::filesystem;
namespace asio = boost::asio;
using asio::ip::tcp;

const std::string MY_INFO = (fs::current_path().u8string() + "\\my.info");
/// <summary>
/// Used for parsing responses from serever
/// Handled dynamic message size.
/// </summary>
/// <param name="client_socket"></param>
/// <returns></returns>
std::vector<uint8_t> read_socket(tcp::socket& client_socket) {
    using namespace boost::asio;

    std::vector<uint8_t> response;
    boost::system::error_code ec;

    // Read the first 7 bytes ( version + code + size)
    std::array<uint8_t, 7> version_code_size;
    read(client_socket, buffer(version_code_size), ec);
    if (ec == asio::error::eof) {
        throw std::exception("Server Disconnected\n");  //Exit when the server disconnects
    }

  

    response.insert(response.end(), version_code_size.begin(), version_code_size.end());

    // Handle different cases based on the status code
    


    // Extract the size field from the 3rd to 6th bytes (little-endian)
    uint32_t size_val = version_code_size[6] << 24 |
        version_code_size[5] << 16 |
        version_code_size[4] << 8 |
        version_code_size[3];

    // Read the payload (size_val bytes)
    std::vector<uint8_t> data(size_val);
    read(client_socket, buffer(data));
    response.insert(response.end(), data.begin(), data.end());

    return response;
}


void store_my_info(const std::string& name, const UUID& uuid, const char* aeskey) {
    std::ofstream ofs(MY_INFO, std::ios::out);
    if (!ofs) {
        throw std::runtime_error("Failed to open file for writing");
    }

    // Write the name as the first line.
    ofs << name << "\n";

    // Convert the 16-byte UUID to a 32-character hex string.
    std::string uuid_hex;
    CryptoPP::StringSource ss_uuid(
        reinterpret_cast<const uint8_t*>(uuid.id.data()), uuid.id.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(uuid_hex), false)  // 'false' disables line breaks
    );
    ofs << uuid_hex << "\n";

    // Base64 encode the AES key.
    const size_t aeskey_length = 16;
    std::string aeskey_b64;
    CryptoPP::StringSource ss_key(
        reinterpret_cast<const uint8_t*>(aeskey), aeskey_length, true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(aeskey_b64), false)  // 'false' disables line breaks
    );
    ofs << aeskey_b64 << "\n";

    ofs.close();
}


void read_my_info(std::string& name, UUID& uuid, char* aeskey) {
    // Open the file for reading.
    std::ifstream ifs(MY_INFO, std::ios::in);
    if (!ifs)
        throw std::runtime_error("Failed to open file for reading");

    // Read the first line: name.
    if (!std::getline(ifs, name))
        throw std::runtime_error("Failed to read name from file");

    // Read the second line: UUID as a 32-character hex string.
    std::string uuid_hex;
    if (!std::getline(ifs, uuid_hex))
        throw std::runtime_error("Failed to read UUID from file");
    if (uuid_hex.size() != 32)
        throw std::runtime_error("UUID hex string must be exactly 32 characters");

    // Decode the hex string into 16 bytes.
    std::string decoded_uuid;
    CryptoPP::StringSource ss_uuid(
        uuid_hex, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded_uuid))
    );
    if (decoded_uuid.size() != 16)
        throw std::runtime_error("Decoded UUID is not 16 bytes");
    // Copy decoded data into uuid.id
    for (size_t i = 0; i < 16; ++i)
        uuid.id[i] = static_cast<uint8_t>(decoded_uuid[i]);

    // Read the third line: AES key in Base64 encoding.
    std::string aeskey_b64;
    if (!std::getline(ifs, aeskey_b64))
        throw std::runtime_error("Failed to read AES key from file");

    // Decode the Base64 string to obtain the raw AES key bytes.
    std::string decoded_aes;
    CryptoPP::StringSource ss_aes(
        aeskey_b64, true,
        new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded_aes))
    );
    if (decoded_aes.size() != 16)
        throw std::runtime_error("Decoded AES key is not 16 bytes");

    // Copy the decoded AES key bytes into the provided aeskey pointer.
    std::memcpy(aeskey, decoded_aes.data(), 16);
}

int main()
{
	
}