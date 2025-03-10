from datetime import datetime
import sqlite3
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "defensive.db")

class ClientEntry:
    UserName:str
    public_key:bytes
    last_seen:datetime

class MessageEntry:
    id:bytes
    from_UUID:bytes
    type:bytes
    content:bytes

class DB:
    messages_table:dict[bytes,MessageEntry]#key is destination UUID
    clients_table:dict[bytes,ClientEntry]#key is UUID
    def __init__(self):
        conn = sqlite3.connect(DB_PATH)#connect to db
        conn.text_factory = bytes
        cursor = conn.cursor()


        cursor.executescript(
             "CREATE TABLE IF NOT EXISTS clients ("+
                "ID BLOB NOT NULL PRIMARY KEY,"+
                "UserName TEXT NOT NULL CHECK(length(UserName) <= 255),"+
                "PublicKey BLOB NOT NULL,"+
                "LastSeen TEXT)"
        )
        cursor.executescript(
            "CREATE TABLE IF NOT EXISTS messages (" +
            "ID BLOB NOT NULL PRIMARY KEY," +
            "ToClient BLOB NOT NULL ," +
            "FromClient BLOB NOT NULL ," +
            "Type INTEGER NOT NULL," +
            "PublicKey BLOB NOT NULL," +
            "LastSeen TEXT)"
        )
        conn.commit()
        conn.close()

    def register_client(self,UUID:bytes,username:str,public_key:bytes)->bool:
        """
        Checks if the UUID exists in the clients table. If not, inserts the UUID, username, and public key.
        """
        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()

        # Check if the username already exists
        cursor.execute("SELECT 1 FROM clients WHERE username = ?", (username,))
        exists = cursor.fetchone()

        if not exists:
            cursor.execute("INSERT INTO clients (ID, UserName, PublicKey, LastSeen) VALUES (?, ?, ?, NULL)"
                , (UUID, username, public_key))
        else:
            connection.commit()
            connection.close()
            return  False
        connection.commit()
        connection.close()
        self.update_time(UUID)
        return True

    def update_time(self,UUID:bytes):
        """
        Updates the LASTSEEN field for a given UUID with the current date and time.
        """
        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()

        # Get current date and time in format "YYYY-MM-DD HH:MM:SS"
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE clients 
            SET LastSeen = ?
            WHERE ID = ?
        """, (current_time, UUID))

        connection.commit()
        connection.close()

    def add_message(self,message_id: bytes, to_client: bytes,from_client: bytes,
                message_type: bytes, content: bytes):
        """
        Adds a message to the 'messages' table in the SQLite database.

        Parameters:
            db_path (str): Path to the SQLite database file.
            message_id (bytes): 4-byte message identifier.
            to_client (bytes): 16-byte recipient client ID.
            from_client (bytes): 16-byte sender client ID.
            message_type (bytes): 1-byte message type.
            content (bytes): Message content (BLOB).

        Raises:
            ValueError: If any of the provided bytes do not match the expected length.
        """
        # Validate byte lengths.
        if len(message_id) != 4:
            raise ValueError("message_id must be exactly 4 bytes")
        if len(to_client) != 16:
            raise ValueError("to_client must be exactly 16 bytes")
        if len(from_client) != 16:
            raise ValueError("from_client must be exactly 16 bytes")
        if len(message_type) != 1:
            raise ValueError("message_type must be exactly 1 byte")

        # Connect to the database.
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Insert the message into the messages table.
        cursor.execute(
            "INSERT INTO messages (ID, ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?, ?)"
        , (
            sqlite3.Binary(message_id),
            sqlite3.Binary(to_client),
            sqlite3.Binary(from_client),
            sqlite3.Binary(message_type),
            sqlite3.Binary(content)
        ))

        # Commit changes and close the connection.
        conn.commit()
        conn.close()


    def get_client_list(self,uuid:bytes)->bytes:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Query to get all clients whose ID (a BLOB) does not match the given uuid.
        query = "SELECT ID, UserName FROM clients WHERE ID != ?"
        cursor.execute(query, (sqlite3.Binary(uuid),))

        # Retrieve all matching rows.
        results = cursor.fetchall()

        conn.close()
        formatted_records = []
        for client in results:
            client_id, username = client

            #Ensure the client ID is exactly 16 bytes
            if len(client_id) != 16:
                raise ValueError("Client ID must be exactly 16 bytes")

            # Convert username to bytes using UTF-8 encoding.
            username_bytes = username.encode("utf-8")

            #Ensure the username part is exactly 255 bytes:
            padded_username = username_bytes.ljust(255, b'\x00')[:255]


            record_bytes = client_id + padded_username
            formatted_records.append(record_bytes)


        return b"".join(formatted_records)


    def get_client_public(self, uuid:bytes)->bytes:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Query to get all clients whose ID (a BLOB) does not match the given uuid.
        query = "SELECT PublicKey FROM clients WHERE ID != ?"
        cursor.execute(query, (sqlite3.Binary(uuid),))

        # Retrieve all matching rows.
        results = cursor.fetchall()

        conn.close()

        return results[0][0]#first record with one field