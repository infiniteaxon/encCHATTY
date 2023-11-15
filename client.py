import socket
import random
import threading
import rsa
import os
import base64
from datetime import datetime
from colorama import Fore, init
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

init()  # Colorama
colors = [Fore.BLUE, Fore.LIGHTBLUE_EX, Fore.CYAN, Fore.LIGHTCYAN_EX,
          Fore.GREEN, Fore.LIGHTGREEN_EX, Fore.RED, Fore.LIGHTRED_EX,
          Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.YELLOW, Fore.LIGHTYELLOW_EX,
          Fore.WHITE]

uCOLOR = random.choice(colors)  # Picks random color for each client

sHOST = input(f"{Fore.GREEN}[!] Enter server IP: {Fore.RESET}")  # Server IP
sPORT = int(input(f"{Fore.GREEN}[!] Enter server Port: {Fore.RESET}"))  # Server Port
sep = "<SEP>"

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Initialize TCP socket
print(f"{Fore.YELLOW}[*] Connecting to {sHOST}:{sPORT}...{Fore.RESET}")  # Return status

tcp.connect((sHOST, sPORT))  # Connect to server
print(f"{Fore.GREEN}[+] Connected {Fore.RESET}")  # Return status

name = input("Enter your name: ")  # Client inputs username


# Create Keys and Open Them
def create_keys_client():
    print(f"{Fore.YELLOW}[*] Generating RSA Keys for Secure Communication... please wait{Fore.RESET}")
    client_public, client_private = rsa.newkeys(2048)
    print(f"{Fore.GREEN}[*] Key successfully generated!")
    return client_public, client_private


# Main key handling function
def use_keys():
    client_public, client_private = create_keys_client()
    tcp.send(client_public.save_pkcs1('PEM'))  # Send the public key to the server right after establishing a connection
    server_public_key_data = tcp.recv(8192)  # Assuming the next message from the server will be its public key
    server_public = rsa.PublicKey.load_pkcs1(server_public_key_data)

    return client_public, client_private, server_public


client_public, client_private, server_public = use_keys()

# Generate AES key
aes_key = os.urandom(32)  # AES key size can be 16, 24, or 32 bytes
encrypted_aes_key = rsa.encrypt(aes_key, server_public)  # Encrypt AES key with server's public RSA key
tcp.send(encrypted_aes_key)  # Send the encrypted AES key to the server


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


def listen(client_private_key):  # Function to listen for messages
    while True:
        try:
            message = tcp.recv(8192)  # When message is received
            decrypted_msg = aes_decrypt(message, aes_key)  # Decrypt Message
            print("\n" + decrypted_msg)  # Print message
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Fore.RESET}")
            break  # Break if error occurs


threading.Thread(target=listen, args=(client_private,),
                 daemon=True).start()  # Listen for messages always, Daemon ends thread when last thread ends

while True:
    sending = input()  # Message being sent
    if sending.lower() == 'q':  # Exit the program
        break
    date_now = datetime.now().strftime('%m-%d-%Y %H:%M:%S')  # Find current date/time
    to_send = f"{uCOLOR}[{date_now}] {name}: {sending}{Fore.RESET}"  # Structure message
    encrypted_message = aes_encrypt(to_send, aes_key)
    tcp.send(encrypted_message)

disconnect_msg = f"{uCOLOR}[{datetime.now().strftime('%m-%d-%Y %H:%M:%S')}] {name} has disconnected.{Fore.RESET}"
encrypted_disconnect_msg = aes_encrypt(disconnect_msg, aes_key)
tcp.send(encrypted_disconnect_msg)

tcp.close()
print(f"{Fore.RED}[!] Connection Closed{Fore.RESET}")
