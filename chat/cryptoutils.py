import random 
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class DiffieHellman:
    """
    Classe que estabelece o protocolo de criptografia Diffie Hellman a fim de gerar a chave de criptografia a ser utilizada no canal de comunicação segura
    """
    @staticmethod
    def power(base: int, exp: int, mod: int):
        return pow(base, exp, mod)

    @staticmethod
    def isPrime(number: int):
        if number <= 1:
            return False
        for i in range(2, int(number ** 0.5) + 1):
            if number % i == 0:
                return False
        return True

    @staticmethod
    def genRandomN(bits: int = 2048):
        return random.getrandbits(bits)
    
    @staticmethod
    def genRandomG():
        return random.randint(1, 15)

    def __init__(self):
        self.n = self.genRandomN()
        g = self.genRandomG()  
        while not self.isPrime(g):
            g = self.genRandomG()
        self.g = g
        self.private_key = random.randint(1, self.n - 1)
        self.public_key = self.power(self.g, self.private_key, self.n)

    def generate_shared_key(self, other_public_key):
        return self.power(other_public_key, self.private_key, self.n)
    

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        if isinstance(key, str):
            key = key.encode('utf-8')  # Converte a chave para bytes se for uma string
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode('utf-8'))
        return b64encode(iv + encrypted_text).decode("utf-8")
    
    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded_text = cipher.decrypt(encrypted_text[self.block_size:])
        return self.__unpad(decrypted_padded_text).decode('utf-8')
    
    def __pad(self, plain_text):
        number_of_bytes = self.block_size - len(plain_text.encode('utf-8')) % self.block_size
        padding_str = chr(number_of_bytes) * number_of_bytes
        return plain_text + padding_str

    def __unpad(self, padded_text):
        last_character = padded_text[-1:]
        return padded_text[:-ord(last_character)]
    
if __name__ == "__main__":
    key = "9469892362713038171105362369428382380867348523120498364775039682255772912515788274121422554243571055132703517952883417242434698165245563574474472654920632588053871168521780698960048152592743318417431538720672783206837093428627500826275714557779899498150252703784389734327371239349487161900124271115110020973202171998116821080565615374233315312062770327902257411254064052175501422266250085726688337949361806869695845110660131892307386747037964748499974734475120058323630586172673779782159579869910941771305380379803453235512771535715463609157757234637004876369639812018413932879375251991186393053721384466996610338697"
    cipher = AESCipher(key)
    message = "Olá Mundo"
    encrypted = cipher.encrypt(message)
    print(f"Encrypted: {encrypted}")

    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")