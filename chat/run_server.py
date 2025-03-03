from server import ChatServer
import socket
import threading

def main():
    host = '127.0.0.1'
    port = 5001
    server = ChatServer(host, port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")
    
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

if __name__ == '__main__':
    main() 