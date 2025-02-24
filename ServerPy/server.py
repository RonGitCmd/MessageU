import socket
import threading




HOST = 'localhost'
PORT = 40607

def handle_client(clientSocket:socket, client_address:str):
   pass



def start_server():
    print(f"[INFO] Starting server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print("[INFO] Server is listening for connections...")

        while True:#Look for connection
            clientSocket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(clientSocket, client_address)).start()

if __name__ == "__main__":
    start_server()
