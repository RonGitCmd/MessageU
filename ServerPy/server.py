import os
import socket
import threading


from protocol_tools import read_socket, Request, CodeTypes, Response
from database import DB





HOST = 'localhost'
PORT = 40607
VERSION = 2

def gen_uuid()->bytes:
    return os.urandom(16)

def handle_client(db: DB, clientSocket:socket, client_address:str):
    try:
        while True:
            packet = read_socket(clientSocket)#wait for client request
            client_request = Request()
            client_request.parse_request(packet)
            UUID = client_request.UUID
            db.update_time(UUID)
            match client_request.code:
                case CodeTypes.REQ_REGISTER:
                    name,public_key = client_request.payload[:255], client_request.payload[255:]
                    username = name.decode().rstrip()
                    UUID = gen_uuid()
                    if db.register_client(UUID,username,public_key):
                        resp = Response()
                        resp.code = CodeTypes.RESP_SUCSESS_REGISTER
                        resp.version = VERSION
                        resp.size = 16
                        resp.payload = UUID
                        clientSocket.sendall(resp.construct_response())
                    else:
                        resp = Response()
                        resp.code = CodeTypes.RESP_ERROR
                        resp.version = VERSION
                        resp.size = 0
                        resp.payload = bytes()
                        clientSocket.sendall(resp.construct_response())
                case CodeTypes.REQ_GETCLIENT_LIST:
                    client_list = bytes()
                    try:
                        client_list = db.get_client_list(UUID)
                    except:
                        resp = Response()
                        resp.code = CodeTypes.RESP_ERROR
                        resp.version = VERSION
                        resp.size = 0
                        resp.payload = bytes()
                        clientSocket.sendall(resp.construct_response())
                        continue
                    resp = Response()
                    resp.code = CodeTypes.RESP_CLIENT_LIST
                    resp.version = VERSION
                    resp.size = len(client_list)
                    resp.payload = client_list
                    clientSocket.sendall(resp.construct_response())
                case CodeTypes.REQ_GETCLIENT_PUBLIC:
                    target_uuid = client_request.payload
                    p_key = bytes()
                    try:
                        p_key = db.get_client_public(target_uuid)
                    except:
                        resp = Response()
                        resp.code = CodeTypes.RESP_ERROR
                        resp.version = VERSION
                        resp.size = 0
                        resp.payload = bytes()
                        clientSocket.sendall(resp.construct_response())
                        continue
                    resp = Response()
                    resp.code = CodeTypes.RESP_CLIENT_PUBLIC
                    resp.version = VERSION
                    resp.payload = target_uuid +p_key
                    resp.size = len(resp.payload)
                    clientSocket.sendall(resp.construct_response())
                case CodeTypes.REQ_PULL_MESAGES:
                    request_uuid =  client_request.UUID
                    try:
                        messages = db.pull_messages(request_uuid)
                    except Exception as e:
                        resp = Response()
                        resp.code = CodeTypes.RESP_ERROR
                        resp.version = VERSION
                        resp.size = 0
                        resp.payload = bytes()
                        clientSocket.sendall(resp.construct_response())
                        continue
                    resp = Response()
                    resp.code = CodeTypes.RESP_PENDING_MESSAGE
                    resp.version = VERSION
                    resp.payload = messages
                    resp.size = len(messages)
                    clientSocket.sendall(resp.construct_response())
                    pass

                case CodeTypes.REQ_SENDCLIENT_MESSAGE:
                    source_id = client_request.UUID
                    target_id = client_request.payload[:16]
                    message_type =  client_request.payload[16].to_bytes(byteorder= 'little',length=1)
                    message_size = int.from_bytes(client_request.payload[17:21], byteorder='little')
                    message_contents = client_request.payload[21:21+message_size]
                    try:
                        m_id = int.to_bytes(db.add_message(target_id,source_id,message_type,message_contents),length=4,byteorder='little')
                    except Exception as e:
                        resp = Response()
                        resp.code = CodeTypes.RESP_ERROR
                        resp.version = VERSION
                        resp.size = 0
                        resp.payload = bytes()
                        clientSocket.sendall(resp.construct_response())
                        continue
                    resp = Response()
                    resp.code = CodeTypes.RESP_MESSAGE_PROCCESED
                    resp.version = VERSION
                    resp.payload = target_id+m_id
                    resp.size = 20
                    clientSocket.sendall(resp.construct_response())







    except ConnectionRefusedError:
        print("Connection refused.")
    except Exception as e:
        print(f"Error: {e}")
        return




def start_server():
    print(f"[INFO] Starting server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print("[INFO] Server is listening for connections...")
        db = DB()
        while True:#Look for connection
            clientSocket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(db, clientSocket, client_address)).start()

if __name__ == "__main__":
    start_server()
