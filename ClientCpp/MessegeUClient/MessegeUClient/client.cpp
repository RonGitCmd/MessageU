#include <cryptopp/cryptlib.h>
#include <boost/asio.hpp>
#include <filesystem>
#include <fstream>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include "protocol_tools.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"
#include "RSAWrapper.h"

namespace fs = std::filesystem;
namespace asio = boost::asio;
using asio::ip::tcp;
const uint8_t VERSION = 1;
const std::string MY_INFO = (fs::current_path().u8string() + "\\my.info");
const std::string SERVER_INFO = (fs::current_path().u8string() + "\\server.info");


tcp::socket connect_to_server(  asio::io_context& io_context)
{
    std::ifstream ifs(SERVER_INFO);
    if (!ifs) {
        throw std::runtime_error("Failed to open server info file: " + SERVER_INFO);
    }

    std::string serverLine;
    if (!std::getline(ifs, serverLine)) {
        throw std::runtime_error("Failed to read server address from file");
    }

    auto colonPos = serverLine.find(':');
    if (colonPos == std::string::npos) {
        throw std::runtime_error("Invalid server address format. Expected 'ip:port'.");
    }

    std::string ip = serverLine.substr(0, colonPos);
    std::string port = serverLine.substr(colonPos + 1);

    // 3) Use Boost.Asio to resolve and connect
    tcp::resolver resolver(io_context);
    tcp::resolver::results_type endpoints = resolver.resolve(ip, port);

    tcp::socket socket(io_context);
    asio::connect(socket, endpoints);

    return socket; // Return the connected socket
}


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


void store_my_info(const std::string& name, const UUID& uuid, std::string rsakey) {
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
    std::string rsakey_b64 = Base64Wrapper::encode(rsakey);

    ofs << rsakey_b64 << "\n";

    ofs.close();
}


std::string read_my_info(std::string& name, UUID& uuid) {
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
    std::string rsakey_b64;
    if (!std::getline(ifs, rsakey_b64))
        throw std::runtime_error("Failed to read AES key from file");

    // Decode the Base64 string to obtain the raw AES key bytes.
    std::string decoded_rsa = Base64Wrapper::decode(rsakey_b64);
  
    return decoded_rsa;

}

int main()
{
    std::string username;
    UUID uuid;
    bool myinfo = false;
    std::unique_ptr<RSAPrivateWrapper> rsapriv;
    asio::io_context io_context;
    tcp::socket socket = connect_to_server(io_context);
    if (fs::exists(MY_INFO))
    {
        myinfo = true;
        rsapriv = std::make_unique< RSAPrivateWrapper>(read_my_info(username, uuid));
    }
    else
        rsapriv = std::make_unique <RSAPrivateWrapper>();


    std::cout << "MessageU client at your service." << std::endl;
    while (true)
    {
        std::cout << std::endl << "110) Register" << std::endl;
        std::cout << "120) Request for clietns list" << std::endl;
        std::cout << "130) Request for public key" << std::endl;
        std::cout << "140) Request for waiting messages" << std::endl;
        std::cout << "150) Send a text message  " << std::endl;
        std::cout << "151) Send a request for symetric key  " << std::endl;
        std::cout << "152) Send your symmetric key" << std::endl;
        std::cout << "  0) Exit client" << std::endl<<"?";
        int req;
        std::cin >> req;
        
        switch (req)
        {
        case 110:
            if (myinfo)
            {
                std::cout << std::endl << "Error: file my.info exists";
                break;
            }
            std::cout << "\nEnter your name: ";
            std::cin >> username;
            Request req; 
            req.code =  static_cast<uint16_t>(Operation::REQ_REGISTER);
            req.version = VERSION;
            req.user_id = UUID();
            // Create a 255-byte vector initialized to zero.
            std::vector<uint8_t> paddedUsername(255, 0);

            // Copy the username into the paddedUsername buffer.
            // Ensure we leave room for the null terminator.
            size_t copyLength = std::min(username.size(), static_cast<size_t>(254));
            std::copy(username.begin(), username.begin() + copyLength, paddedUsername.begin());
            paddedUsername[copyLength] = '\0'; //null terminator
           
            std::string rsaPub = rsapriv->getPublicKey();
            

            // Create the payload: first the 255-byte padded username, then the RSA public key.
            req.payload = paddedUsername; // copy padded username
            req.payload.insert(req.payload.end(), rsaPub.begin(), rsaPub.end());

        
            req.size = static_cast<uint32_t>(req.payload.size());
            
            socket.send(construct_request(req));
            
            break;
        }
    }

    socket.close();

}