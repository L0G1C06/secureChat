import socket
import threading
import hashlib
from dotenv import load_dotenv
import os

from cryptoutils import DiffieHellman, AESCipher

load_dotenv()

HOST = os.getenv("HOST")
PORT = os.getenv("PORT")

# Função para receber mensagens do servidor
def receive_messages(client, dh, aes):
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
                #print(f"Chave pública recebida: {public_key}, Chave compartilhada gerada: {shared_key}")

                # Ensure the shared_key is converted to bytes before hashing
                shared_key_bytes = str(shared_key).encode('utf-8')
                aes.key = hashlib.sha256(shared_key_bytes).digest()
                print("Chave AES configurada.")
            else:
                # Apenas imprime a mensagem recebida
                if aes:  # Check if aes is initialized before decryption
                    decrypted_message = aes.decrypt(message_str)
                    print("Mensagem recebida:", decrypted_message)
                else:
                    print("Chave compartilhada ainda não estabelecida.")
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")
            client.close()
            break

# Função para enviar mensagens ao servidor
def send_messages(client, aes):
    while True:
        message = input()
        encrypted_message = aes.encrypt(message)
        client.send(encrypted_message.encode('utf-8'))  # Envia a mensagem como texto codificado em UTF-8

# Configuração do cliente
def start_client(name):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, int(PORT)))

    print(f"Conectado como {name}")

    data = client.recv(1024).decode()
    n, g = map(int, data.split(','))
    #print("N: ", n)
    #print("G: ", g)

    dh = DiffieHellman()
    dh.n = n
    dh.g = g
    dh.public_key = dh.power(dh.g, dh.private_key, dh.n)
    #print(f"Public key: {name}: {dh.public_key}")
    client.send(str(dh.public_key).encode())

    # Initialize AES with a dummy key; it will be updated later
    aes = AESCipher(b'0' * 16)

    # Iniciando threads para enviar e receber mensagens
    receive_thread = threading.Thread(target=receive_messages, args=(client, dh, aes))
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(client, aes))
    send_thread.start()

if __name__ == "__main__":
    name = input("Digite seu nome: ")
    start_client(name)