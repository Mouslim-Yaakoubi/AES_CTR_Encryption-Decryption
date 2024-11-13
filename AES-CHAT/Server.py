import socket
import threading
import os
from ctr import AES

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = {}  # {client_socket: (username, key)}
        print(f"Server started on {host}:{port}")

    def handle_client(self, client_socket, address):
        try:
            # Receive username length
            username_length = int.from_bytes(client_socket.recv(4), 'big')
            # Receive username
            username = client_socket.recv(username_length).decode('utf-8')
            
            # Generate unique key for this client
            client_key = os.urandom(16)
            aes = AES(client_key)
            print(client_key)
            
            # Send key to client
            client_socket.send(client_key)
            
            # Store client info
            self.clients[client_socket] = (username, client_key)
            
            # Broadcast welcome message
            welcome_message = f"{username} has joined the chat!"
            print(welcome_message)
            self.broadcast(welcome_message.encode(), client_socket)

            while True:
                try:
                    # Receive message length
                    msg_length = int.from_bytes(client_socket.recv(4), 'big')
                    if msg_length == 0:
                        break

                    # Receive encrypted message
                    encrypted_message = client_socket.recv(msg_length)
                    if not encrypted_message:
                        break

                    # Decrypt message
                    iv = encrypted_message[:16]  # First 16 bytes are IV
                    ciphertext = encrypted_message[16:]  # Rest is ciphertext
                    decrypted_message = aes.decrypt_ctr(ciphertext, iv)
                    
                    # Broadcast message
                    message_to_broadcast = f"{username}: {decrypted_message.decode('utf-8')}"
                 
                    self.broadcast(message_to_broadcast.encode(), client_socket)

                except Exception as e:
                    print(f"Error handling message from {username}: {e}")
                    break

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            self.remove_client(client_socket)

    def broadcast(self, message, sender_socket):
        for client_socket in list(self.clients.keys()):
            if client_socket != sender_socket:
                try:
                    username, key = self.clients[client_socket]
                    aes = AES(key)
                    
                    # Generate new IV for each message
                    iv = os.urandom(16)
                    encrypted_message = aes.encrypt_ctr(message, iv)
                    
                    # Send message length first (including IV)
                    full_message = iv + encrypted_message
                    message_length = len(full_message).to_bytes(4, 'big')
                    client_socket.send(message_length)
                    client_socket.send(full_message)
                except:
                    self.remove_client(client_socket)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            username, _ = self.clients[client_socket]
            del self.clients[client_socket]
            client_socket.close()
            leave_message = f"{username} has left the chat!"
            print(leave_message)
            self.broadcast(leave_message.encode(), client_socket)

    def start(self):
        print("Server is listening...")
        while True:
            client_socket, address = self.server.accept()
            print(f"Connected with {address}")
            thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
            thread.daemon = True
            thread.start()

if __name__ == "__main__":
    server = ChatServer()
    server.start()