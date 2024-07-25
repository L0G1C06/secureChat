import socket
import threading

from cryptoutils import DiffieHellman

# Lista para armazenar clientes conectados
clients = []

# Função para enviar mensagens a todos os clientes conectados
def broadcast(message, _client):
    for client in clients:
        if client['socket'] != _client:
            client['socket'].send(message.encode('utf-8'))

# Função para lidar com cada cliente
def handle_client(client_socket, client_address):
    try:
        # Receber chave pública do cliente
        public_key = int(client_socket.recv(1024).decode())
        
        # Armazenar cliente e sua chave pública
        client_info = {'socket': client_socket, 'address': client_address, 'public_key': public_key}
        clients.append(client_info)

        # Enviar chaves públicas dos outros clientes para o novo cliente
        for client in clients:
            if client['socket'] != client_socket:
                client_socket.send(f"KEY:{client['public_key']}".encode())
                client['socket'].send(f"KEY:{public_key}".encode())

        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                broadcast(message, client_socket)
    except Exception as e:
        print(f"Erro: {e}")
        clients.remove(next(client for client in clients if client['socket'] == client_socket))
        client_socket.close()

# Configuração do servidor
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 5555))
    server.listen()

    print("Servidor de chat iniciado...")

    dh = DiffieHellman()
    n = dh.n
    g = dh.g

    while True:
        client_socket, client_address = server.accept()
        print(f"Conexão estabelecida com {client_address}")

        # Enviar n e g para o cliente
        client_socket.send(f"{n},{g}".encode())

        thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        thread.start()

if __name__ == "__main__":
    start_server()
