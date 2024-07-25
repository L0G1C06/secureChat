import socket
import threading
from cryptoutils import DiffieHellman

# Função para receber mensagens do servidor
def receive_messages(client, dh):
    while True:
        try:
            message = client.recv(1024)  # Recebe a mensagem como binário
            if not message:
                break

            # Decodifica a mensagem para string
            message_str = message.decode('utf-8', errors='replace')  # Usa 'replace' para substituir caracteres inválidos
            if message_str.startswith("KEY:"):
                public_key = int(message_str.split(":")[1])
                shared_key = dh.generate_shared_key(public_key)
                print(f"Chave pública recebida: {public_key}, Chave compartilhada gerada: {shared_key}")
                # Atualize a chave compartilhada se necessário, mas sem usar AES para criptografia
            else:
                # Apenas imprime a mensagem recebida
                print("Mensagem recebida:", message_str)
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")
            client.close()
            break

# Função para enviar mensagens ao servidor
def send_messages(client):
    while True:
        message = input()
        client.send(message.encode('utf-8'))  # Envia a mensagem como texto codificado em UTF-8

# Configuração do cliente
def start_client(name):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 5555))

    print(f"Conectado como {name}")

    data = client.recv(1024).decode()
    n, g = map(int, data.split(','))
    print("N: ", n)
    print("G: ", g)

    dh = DiffieHellman()
    dh.n = n
    dh.g = g
    dh.public_key = dh.power(dh.g, dh.private_key, dh.n)
    print(f"Public key: {name}: {dh.public_key}")
    client.send(str(dh.public_key).encode())

    # Iniciando threads para enviar e receber mensagens
    receive_thread = threading.Thread(target=receive_messages, args=(client, dh))
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(client,))
    send_thread.start()

if __name__ == "__main__":
    name = input("Digite seu nome: ")
    start_client(name)