from client import ChatClient

def main():
    host = '127.0.0.1'
    port = 5001
    client = ChatClient(host, port)
    client.start()

if __name__ == '__main__':
    main() 