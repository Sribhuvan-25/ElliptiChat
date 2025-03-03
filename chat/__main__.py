import argparse
import socket
import threading
from server import ChatServer
from client import ChatClient

def main():
    parser = argparse.ArgumentParser(description='Secure Chat Application')
    parser.add_argument('mode', choices=['server', 'client'], help='Run as server or client')
    parser.add_argument('--host', default='127.0.0.1', help='Host address')
    parser.add_argument('--port', type=int, default=5000, help='Port number')
    
    args = parser.parse_args()
    
    if args.mode == 'server':
        server = ChatServer(args.host, args.port)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((args.host, args.port))
        server_socket.listen(5)
        print(f"Server listening on {args.host}:{args.port}")
        
        while server.running:
            try:
                client_socket, addr = server_socket.accept()
                print(f"New connection from {addr}")
                client_thread = threading.Thread(
                    target=server.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
                break
                
    else:  # client mode
        client = ChatClient(args.host, args.port)
        client.start()

if __name__ == '__main__':
    main() 