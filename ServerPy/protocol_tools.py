from enum import Enum
import socket
class CodeTypes(Enum):
    REQ_REGISTER = 600
    REQ_GETCLIENT_LIST = 601
    REQ_GETCLIENT_PUBLIC = 602
    REQ_SENDCLIENT_MESSAGE = 603
    REQ_PULLMESAGES = 604
    RESP_SUCSESS_REGISTER = 2100
    RESP_CLIENT_LIST = 2101
    RESP_CLIENT_PUBLIC = 2102
    RESP_MESSAGE_PROCCESED = 2103
    RESP_PENDINGMESSAGE = 2104
    RESP_ERROR = 9000

class Request:
    UUID:bytes
    version:int
    code:CodeTypes
    size:int
    payload:bytes
    def __init__(self):
        pass

    def parse_request(self, raw_bytes:bytes):
        self.UUID = raw_bytes[:16]
        self.version = raw_bytes[16]
        raw_code = int.from_bytes(raw_bytes[17:19],byteorder='little')
        self.code = CodeTypes(raw_code)
        self.size =  int.from_bytes(raw_bytes[19:23], byteorder="little")
        self.payload = raw_bytes[23:]


class Response:
    version:int
    code:CodeTypes
    size:int
    payload:bytes

    def __init__(self):
        pass

    def construct_response(self)->bytes:
        packet =  self.version.to_bytes(1,byteorder='little')
        packet = packet + self.code.value.to_bytes(length = 2, byteorder= 'little')
        packet = packet + self.size.to_bytes(length=4, byteorder= 'little')
        packet = packet + self.payload
        return packet

def read_socket( client_socket:socket)->bytes:
    ID_version_code_size = client_socket.recv(23)
    size = int.from_bytes(ID_version_code_size[19:22], byteorder="little")
    return ID_version_code_size + client_socket.recv(size)
