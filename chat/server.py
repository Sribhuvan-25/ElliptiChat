from crypto_utils import generate_ecc_keypair, serialize_public_key, deserialize_public_key, derive_shared_key
from crypto_utils import aes_encrypt, aes_decrypt

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.server_private_key, self.server_public_key = generate_ecc_keypair()
        self.shared_key = None
        self.clients = {}  # Support multiple clients
        self.running = True

    def handle_client(self, client_socket, addr):
        try:
            # Key exchange
            serialized_pub = serialize_public_key(self.server_public_key)
            client_socket.sendall(serialized_pub)
            
            client_pub_bytes = client_socket.recv(2048)
            client_public_key = deserialize_public_key(client_pub_bytes)
            
            shared_key = derive_shared_key(self.server_private_key, client_public_key)
            client_id = f"Client-{addr[1]}"  # Use port number as client ID
            self.clients[client_socket] = {
                'address': addr,
                'public_key': client_public_key,
                'shared_key': shared_key,
                'id': client_id
            }
            print(f"\n[SERVER] {client_id} connected from {addr[0]}")
            
            # Broadcast welcome message
            welcome_msg = f"{client_id} joined the chat"
            self.broadcast_message(client_socket, welcome_msg.encode('utf-8'))
            
            # Message handling loop
            while self.running:
                length_data = client_socket.recv(4)
                if not length_data:
                    break
                    
                msg_length = int.from_bytes(length_data, 'big')
                data = client_socket.recv(msg_length)
                
                if not data:
                    break
                    
                # Show encrypted data first
                print(f"\n[{client_id}] Encrypted: {data.hex()[:64]}...")  # Show first 32 bytes of encrypted data
                
                # Decrypt and verify
                iv = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]
                
                try:
                    plaintext = aes_decrypt(shared_key, iv, ciphertext, tag)
                    print(f"[{client_id}] Decrypted: {plaintext.decode('utf-8')}")
                    
                    # Add client ID to the message before broadcasting
                    formatted_msg = f"{client_id}: {plaintext.decode('utf-8')}"
                    self.broadcast_message(client_socket, formatted_msg.encode('utf-8'))
                except Exception as e:
                    print(f"Decryption error: {e}")
                    
        except Exception as e:
            print(f"\n[SERVER] Error handling {client_id}: {e}")
        finally:
            self.remove_client(client_socket)

    def broadcast_message(self, sender_socket, message):
        """Send message to all other connected clients"""
        for client_socket in self.clients:
            if client_socket != sender_socket:
                try:
                    shared_key = self.clients[client_socket]['shared_key']
                    iv, ciphertext, tag = aes_encrypt(shared_key, message)
                    
                    # Send length prefix
                    msg_data = iv + tag + ciphertext
                    length_prefix = len(msg_data).to_bytes(4, 'big')
                    client_socket.sendall(length_prefix + msg_data)
                except Exception as e:
                    print(f"Error broadcasting to client: {e}")

    def remove_client(self, client_socket):
        """Clean up disconnected client"""
        if client_socket in self.clients:
            addr = self.clients[client_socket]['address']
            del self.clients[client_socket]
            client_socket.close()
            print(f"Client {addr} disconnected") 