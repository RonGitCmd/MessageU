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
    while True:
        packet = read_socket(clientSocket)#wait for client request
        client_request = Request()
        client_request.parse_request(packet)
        UUID = gen_uuid()
        match client_request.code:
            case CodeTypes.REQ_REGISTER:
                name,public_key = client_request.payload[:255], client_request.payload[255:]
                username = str(name)
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
