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
#include <string>
#include <map>
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

//*/
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


const std::string read_my_info(std::string& name, UUID& uuid) {
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

    // Read the rest: RS key in Base64 encoding.
    std::string rsakey_b64;
    std::ostringstream oss;
    oss << ifs.rdbuf();  // reads until EOF from the current file position
    rsakey_b64 = oss.str();

    // Decode the Base64 string to obtain the raw RSA key bytes.
    std::string decoded_rsa = Base64Wrapper::decode(rsakey_b64);
  
    return decoded_rsa;

}

int main()
{
    try
    {
        std::string username;
        UUID uuid = UUID();
        bool myinfo = false;
        std::unique_ptr<RSAPrivateWrapper> rsapriv;
        asio::io_context io_context;
        tcp::socket socket = connect_to_server(io_context);
        std::map<std::string, UUID> nameToUUID;
        std::map<UUID, std::string> UUIDToName;
        std::map<UUID, std::unique_ptr<RSAPublicWrapper>> publickeyList;
        std::map<UUID, std::unique_ptr<AESWrapper>> AesList;
        // Check if my.info exists
        if (fs::exists(MY_INFO)) {
            myinfo = true;
            // read_my_info returns a std::string for the private key
            std::string privateKey = read_my_info(username, uuid);
            // Construct the RSAPrivateWrapper from that private key
            rsapriv = std::make_unique<RSAPrivateWrapper>(privateKey);
        }
        else {
            // If file doesn't exist, use the default constructor
            rsapriv = std::make_unique<RSAPrivateWrapper>();
        }
        
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
            std::cout << "  0) Exit client" << std::endl << "?";
            int userinput;
            std::cin >> userinput;

            switch (userinput)
            {
                case 0://exit
                {
                    std::cout << "Exiting client." << std::endl;
                    socket.close();
                    return 0;
                }
                case 110://register
                {
                    if (myinfo)
                    {
                        std::cout << std::endl << "Error: file my.info exists";
                        break;
                    }
                    std::cout << "\nEnter your name: ";
                    std::cin.clear();
                    std::cin.get(); // this will consume the newline
                    std::getline(std::cin, username);
                    Request req;
                    req.code = static_cast<uint16_t>(Operation::REQ_REGISTER);
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

                    socket.send(boost::asio::buffer(construct_request(req)));

                    Response resp = parse_response(read_socket(socket));

                    if (resp.code == static_cast<uint16_t> (Operation::RESP_SUCSESS_REGISTER))
                    {
                        std::memcpy(uuid.id.data(), resp.payload.data(), 16);
                        store_my_info(username, uuid, rsapriv->getPrivateKey());
                        std::cout << "Successfully registered with server." << std::endl;
                    }
                    else
                    {
                        std::cout << "Error registering with server." << std::endl;
                    }

                    break;

                }
                case 120://client list
                {
                    Request req;
                    req.code = static_cast<uint16_t>(Operation::REQ_GETCLIENT_LIST);
                    req.version = VERSION;
                    req.user_id = uuid;
                    req.size = 0;
                    req.payload = std::vector<uint8_t>(0);
                    socket.send(boost::asio::buffer(construct_request(req)));
                    Response resp = parse_response(read_socket(socket));
                    if (resp.code == static_cast<uint16_t> (Operation::RESP_CLIENT_LIST))
                    {
                        nameToUUID = extractClientMap(resp.payload);
                        std::cout << "Clients registered with the server:" << std::endl;
                        for (const auto& [uname, UUID] : nameToUUID)
                        {
                            UUIDToName[UUID] = uname;//add clients to the uuid to name map
                            std::cout << uname << std::endl;
                        }
                    }
                    else
                    {
                        std::cout << "Error Response from server." << std::endl;
                    }
                    break;
                }
                case 130://client key
                {
                    std::cout << "Enter Requested client username: ";
                    std::string target_name;
                    std::cin.clear();
                    std::cin.get(); // this will consume the newline
                    std::getline(std::cin, target_name);
                    UUID target_uuid;
                    if (nameToUUID.find(target_name) != nameToUUID.end())//Target name is found in the client lis
                        target_uuid = nameToUUID[target_name];
                    else
                    {
                        std::cout << "ERROR: Client name entered is not found." << std::endl;
                        break;// if name is not found exit the case
                    }

                    Request req;
                    req.code = static_cast<uint16_t>(Operation::REQ_GETCLIENT_PUBLIC);
                    req.version = VERSION;
                    req.user_id = uuid;
                    req.payload.insert(req.payload.begin(), target_uuid.id.begin(), target_uuid.id.end());
                    req.size = req.payload.size();
                    socket.send(boost::asio::buffer(construct_request(req)));
                    Response resp = parse_response(read_socket(socket));
                    if (resp.code == static_cast<uint16_t> (Operation::RESP_CLIENT_PUBLIC))
                    {
                        std::array<std::uint8_t, 16> p_uuid;
                        std::copy(resp.payload.begin(), resp.payload.begin() + 16, p_uuid.begin());

                        std::array<std::uint8_t, 160> p_key;
                        std::copy(resp.payload.begin() + 16, resp.payload.begin() + 176, p_key.begin());

                        UUID n_uuid;
                        std::copy(p_uuid.begin(), p_uuid.end(), n_uuid.id.begin());
                        

                        std::string key_str(p_key.begin(), p_key.end());
                        publickeyList[n_uuid] = std::make_unique<RSAPublicWrapper>(key_str);//add entry to public key list
                        std::cout << "Client " << target_name << " Public key retrieved server." << std::endl;
                    }
                    else
                    {
                        std::cout << "Error Response from server." << std::endl;
                    }
                    break;
                    
                }

                case 140: //Pull messages
                {
                    Request req;
                    req.code = static_cast<uint16_t>(Operation::REQ_PULLMESAGES);
                    req.version = VERSION;
                    req.user_id = uuid;
                    req.size = 0;
                    req.payload = std::vector<uint8_t>(0);
                    socket.send(boost::asio::buffer(construct_request(req)));
                    Response resp = parse_response(read_socket(socket));
                    std::vector<ClientMessage> pulled_messages = parseMessages(resp.payload);
                    
                    if (resp.code == static_cast<uint16_t> (Operation::RESP_PENDINGMESSAGE))
                    {
                        for (int i = 0; i < pulled_messages.size(); i++)
                        {
                            std::string clientName;
                            if (UUIDToName.find(pulled_messages[i].source_uuid) != UUIDToName.end())//Target name is found in the client lis
                                clientName = UUIDToName[pulled_messages[i].source_uuid];
                            else
                            {
                                std::string uuid_hex;
                                CryptoPP::StringSource ss_uuid(
                                    reinterpret_cast<const uint8_t*>(pulled_messages[i].source_uuid.id.data()), pulled_messages[i].source_uuid.id.size(), true,
                                    new CryptoPP::HexEncoder(new CryptoPP::StringSink(uuid_hex), false)  // 'false' disables line breaks
                                );
                                std::cout << "ERROR: No client name is associated with the UU   ID: " << uuid_hex << std::endl;
                                break;// if name is not found exit the case
                            }

                            std::cout << "From: " << clientName << std::endl << "Content:" << std::endl;


                            switch (pulled_messages[i].message_type)
                            {
                                case MessageTypes::REQ_SYM://received a request for a symetric key
                                    break;
                                case MessageTypes::SEND_SYM://received a symetric key
                                    break;

                                case MessageTypes::SEND_TEXT_MESSAGE://received a text msg
                                    std::cout << pulled_messages[i].content<<std::endl;

                                    break;

                                case MessageTypes::SEND_FILE: //received a file
                                    break;
                            }

                            std::cout << "." << std::endl << "." << std::endl << "-----<EOM>-----" << std::endl << "\\n" << std::endl;

                        }
                    }
                    else
                    {
                        std::cout << "Error Response from server." << std::endl;
                    }



                    break;
                }

                case 150://send a text message
                {
                    std::cout << "Enter recipient name: ";
                    std::string target_name;
                    std::cin.clear();
                    std::cin.get(); // this will consume the newline
                    std::getline(std::cin, target_name);
                    UUID target_uuid;
                    if (nameToUUID.find(target_name) != nameToUUID.end())//Target name is found in the client lis
                        target_uuid = nameToUUID[target_name];
                    else
                    {
                        std::cout << "ERROR: Client name entered is not found."<<std::endl;
                        break;// if name is not found exit the case
                    }

                    std::cout << "Enter Text message: ";
                    std::string text_message;
                    std::cin.clear();

                    std::getline(std::cin, text_message);

                    Request req;
                    req.code = static_cast<uint16_t>(Operation::REQ_SENDCLIENT_MESSAGE);
                    req.version = VERSION;
                    req.user_id = uuid;
                    req.payload.insert(req.payload.begin(), target_uuid.id.begin(), target_uuid.id.end());
                    req.payload.push_back(static_cast<uint8_t> (MessageTypes::SEND_TEXT_MESSAGE));
                    uint32_t text_len = static_cast<uint32_t>(text_message.size());
                    const uint8_t* length_ptr = reinterpret_cast<const uint8_t*>(&text_len);
                    req.payload.insert(req.payload.end(), length_ptr, length_ptr + sizeof(text_len));

                    // Finally, append the actual message bytes.
                    req.payload.insert(req.payload.end(), text_message.begin(), text_message.end());

                    req.size = req.payload.size();
                    socket.send(boost::asio::buffer(construct_request(req)));
                    Response resp = parse_response(read_socket(socket));

                    if (resp.code == static_cast<uint16_t> (Operation::RESP_MESSAGE_PROCCESED))
                    {
                        std::array<std::uint8_t, 16> t_uuid;
                        std::copy(
                            resp.payload.begin(),
                            resp.payload.begin() + 16,
                            t_uuid.begin()
                        );
                                                
                        uint32_t m_id = 0;
                        std::memcpy(&m_id, resp.payload.data() + 16, sizeof(m_id));


                        UUID n_uuid;
                        std::copy(t_uuid.begin(), t_uuid.end(), n_uuid.id.begin());
                        if (n_uuid != target_uuid)
                        {
                            std::cout << "ERROR: uuid received via reply from server doesn't match.";
                            break;
                        }
                        std::cout << "Message with id " << m_id << " successfully received by server";
                        }
                    else
                    {
                        std::cout << "Error Response from server." << std::endl;
                    }
                    break;

                }

                default:
                {
                    break;
                }
            }

        }

        socket.close();
    }
    catch (std::exception ex)
    {
        std::cout << "ERROR: " << ex.what() << std::endl;
        return -1;
    }
    return 0;
}