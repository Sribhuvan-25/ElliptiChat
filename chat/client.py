import socket
import threading
from crypto_utils import generate_ecc_keypair, serialize_public_key, deserialize_public_key, derive_shared_key
from crypto_utils import aes_encrypt, aes_decrypt

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = generate_ecc_keypair()
        self.shared_key = None
        self.running = True

    def start(self):
        try:
            self.socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            
            # Key exchange
            server_pub_bytes = self.socket.recv(2048)
            server_public_key = deserialize_public_key(server_pub_bytes)
            
            serialized_pub = serialize_public_key(self.public_key)
            self.socket.sendall(serialized_pub)
            
            self.shared_key = derive_shared_key(self.private_key, server_public_key)
            
            # Start message handling threads
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            self.send_messages()
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.running = False
            self.socket.close()

    def send_messages(self):
        """Handle sending messages"""
        try:
            print("\nWelcome to the chat! Type 'quit' to exit.")
            while self.running:
                print("You> ", end='', flush=True)
                message = input()
                if message.lower() == 'quit':
                    self.running = False
                    break
                
                if message:  # Only send non-empty messages
                    # Encrypt and send
                    iv, ciphertext, tag = aes_encrypt(self.shared_key, message)
                    msg_data = iv + tag + ciphertext
                    length_prefix = len(msg_data).to_bytes(4, 'big')
                    self.socket.sendall(length_prefix + msg_data)
                    
        except Exception as e:
            print(f"\nError sending message: {e}")
            self.running = False

    def receive_messages(self):
        """Handle receiving messages"""
        try:
            while self.running:
                length_data = self.socket.recv(4)
                if not length_data:
                    break
                    
                msg_length = int.from_bytes(length_data, 'big')
                data = self.socket.recv(msg_length)
                
                if not data:
                    break
                    
                # Decrypt and verify
                iv = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]
                
                try:
                    plaintext = aes_decrypt(self.shared_key, iv, ciphertext, tag)
                    print(f"\r\033[K{plaintext.decode('utf-8')}")  # Clear line and print message
                    print("\r\033[KYou> ", end='', flush=True)  # Reprint prompt
                except Exception as e:
                    print(f"\r\033[KDecryption error: {e}")
                    print("\r\033[KYou> ", end='', flush=True)
                    
        except Exception as e:
            if self.running:  # Only show error if we didn't quit intentionally
                print(f"\r\033[KError receiving message: {e}")
                print("\r\033[KYou> ", end='', flush=True)
            self.running = False 