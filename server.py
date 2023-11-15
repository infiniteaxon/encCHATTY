import socket
import threading
import rsa
import os
import base64
from colorama import Fore, init
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

init()  # Colorama
colors = [Fore.BLUE, Fore.LIGHTBLUE_EX, Fore.CYAN, Fore.LIGHTCYAN_EX,
          Fore.GREEN, Fore.LIGHTGREEN_EX, Fore.RED, Fore.LIGHTRED_EX,
          Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.YELLOW, Fore.LIGHTYELLOW_EX,
          Fore.WHITE]

# Server Connection Info
sHOST = socket.gethostbyname(socket.gethostname())
sPORT = 2003

print(f"{Fore.YELLOW}[*] Creating RSA Keys for Secure Communication... please wait{Fore.RESET}")
server_public, server_private = rsa.newkeys(2048)
print(f"{Fore.GREEN}[*] Key successfully generated!")
client_keys = {}  # Dictionary to store public keys
client_aes_keys = {}  # Dictionary to store AES keys
# Initiate Client Sockets
cSOCKETS = set()
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP Socket
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Set Socket to be Reusable
tcp.bind((sHOST, sPORT))  # Bind Socket to Server
tcp.listen(5)  # Only 5 Connection can queue at once
print(f"{Fore.GREEN}[*] Live on {sHOST}:{sPORT} {Fore.RESET}")  # Print Socket Connection Info


def aes_encrypt(message, key):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Ensure message is in bytes
    message_bytes = message.encode('utf-8')

    encrypted_message = encryptor.update(message_bytes) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message)  # Encode in Base64


def aes_decrypt(encrypted_message, key):
    try:
        decoded_message = base64.b64decode(encrypted_message)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{Fore.RED}[!] Error decoding message: {e}{Fore.RESET}")

    if len(decoded_message) < 16:
        raise ValueError(f"{Fore.RED}[!] Encrypted message too short to contain IV.{Fore.RESET}")

    iv = decoded_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(decoded_message[16:]) + decryptor.finalize()

    try:
        return decrypted_data.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError(f"{Fore.RED}[!] Decrypted data is not valid UTF-8{Fore.RESET}")


# Function to broadcast messages to all clients
def broadcast(message):
    for clientSOCKET in cSOCKETS:
        aes_key = client_aes_keys[clientSOCKET]  # AES key for the client
        encrypted_msg = aes_encrypt(message, aes_key)
        clientSOCKET.send(encrypted_msg)


# Function to Listen for Client Connections
def client_connect(cSOCKET):
    while True:
        try:
            encrypted_aes_key = cSOCKET.recv(8192)
            aes_key = rsa.decrypt(encrypted_aes_key, server_private)  # Decrypt AES key
            client_aes_keys[cSOCKET] = aes_key
            while True:
                message = cSOCKET.recv(8192)
                decrypted_msg = aes_decrypt(message, aes_key)
                broadcast(decrypted_msg)
        except Exception as e:  # Error Handling
            print(f"{Fore.RED}[!] Error: {e} {Fore.RESET}")
            cSOCKETS.remove(cSOCKET)  # Remove bad clients
            broadcast(f"{Fore.YELLOW}[!] A user has disconnected.{Fore.RESET}")
            cSOCKET.close()
            break


# Accept new client connections
try:
    while True:
        cSOCKET, uADDRESS = tcp.accept()
        print(f"{Fore.GREEN}[+] {uADDRESS} connected. {Fore.RESET}")
        cSOCKETS.add(cSOCKET)
        client_public_key_data = cSOCKET.recv(8192)  # Receive client's public key
        client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_data)
        cSOCKET.send(server_public.save_pkcs1('PEM'))  # Send server's public key to the client
        threading.Thread(target=client_connect, args=(cSOCKET,), daemon=True).start()
except KeyboardInterrupt:
    print(f"{Fore.Yellow}[*] Server shutting down...{Fore.RESET}")
finally:
    for client in cSOCKETS:
        client.close()
    tcp.close()
