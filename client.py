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

init()  # Colorama initialization
colors = [Fore.BLUE, Fore.LIGHTBLUE_EX, Fore.CYAN, Fore.LIGHTCYAN_EX,
          Fore.GREEN, Fore.LIGHTGREEN_EX, Fore.RED, Fore.LIGHTRED_EX,
          Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.YELLOW, Fore.LIGHTYELLOW_EX,
          Fore.WHITE]

uCOLOR = random.choice(colors)  # Random color for each client

sHOST = input(f"{Fore.GREEN}[!] Enter server IP: {Fore.RESET}")  # Server IP
sPORT = int(input(f"{Fore.GREEN}[!] Enter server Port: {Fore.RESET}"))  # Server Port

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Initialize TCP socket
print(f"{Fore.YELLOW}[*] Connecting to {sHOST}:{sPORT}...{Fore.RESET}")
tcp.connect((sHOST, sPORT))  # Connect to server
print(f"{Fore.GREEN}[+] Connected {Fore.RESET}")

name = input("Enter your name: ")  # Client username


def use_keys():
    print(f"{Fore.YELLOW}[*] Generating RSA Keys for Secure Communication... please wait{Fore.RESET}")
    client_public, client_private = rsa.newkeys(2048)
    print(f"{Fore.GREEN}[*] Key successfully generated!")
    tcp.send(client_public.save_pkcs1('PEM'))  # Send public key to server
    print(f"{Fore.GREEN}[*] Client Public Key Sent to Server{Fore.RESET}")

    server_public_key_data = tcp.recv(8192)  # Receive server's public key

    if not server_public_key_data.startswith(b'-----BEGIN RSA PUBLIC KEY-----'):
        print(f"{Fore.RED}[!!] Invalid public key format received from server{Fore.RESET}")
        return None, None, None

    server_public = rsa.PublicKey.load_pkcs1(server_public_key_data)
    print(f"{Fore.GREEN}[*] Server Public Key Loaded{Fore.RESET}")
    return client_public, client_private, server_public


client_public, client_private, server_public = use_keys()

aes_key = None


def aes_encrypt(message, key):
    iv = os.urandom(16)  # Generate a new IV for each message
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    message_bytes = message.encode()
    encrypted_message = encryptor.update(message_bytes) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message)  # Prepend IV to encrypted message


def aes_decrypt(encrypted_message_get, key):
    decoded_message = base64.b64decode(encrypted_message_get)
    iv = decoded_message[:16]  # Extract the first 16 bytes as the IV
    encrypted_data = decoded_message[16:]  # The rest is the encrypted data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode()


def add_base64_padding(encoded_str):
    padding_needed = (4 - len(encoded_str) % 4) % 4
    return encoded_str + ('=' * padding_needed)


def listen():
    global aes_key
    while True:
        try:
            message = tcp.recv(8192)
            if not message:
                break  # Server disconnected
            if message.startswith(b'NEW_USER#'):
                message_content = message.decode()
                _, user_address, encoded_key = message_content.split('#', 2)
                print(f"{Fore.YELLOW}[!] New user joined: {user_address}{Fore.RESET}")
                encoded_key = add_base64_padding(encoded_key)
                client_public_key_data = base64.b64decode(encoded_key)
                client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_data)
                print(f"{Fore.GREEN}[*] Public Key received from {user_address}{Fore.RESET}")

                if aes_key:
                    encrypted_aes_key = rsa.encrypt(aes_key, client_public_key)
                    tcp.send(b"AES_KEY:" + encrypted_aes_key)
            elif message.startswith(b"FIRST"):
                aes_key = os.urandom(32)
                print(f"{Fore.GREEN}[+] You are the first client. AES key generated.{Fore.RESET}")
            elif message.startswith(b"AES_KEY:"):
                try:
                    encrypted_aes_key = message[len(b"AES_KEY:"):]
                    aes_key = rsa.decrypt(encrypted_aes_key, client_private)
                    print(f"{Fore.GREEN}[+] AES Key received and set up.{Fore.RESET}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Message Ignored - Contained AES Key for New Client: {e}")
            else:
                try:
                    decrypted_msg = aes_decrypt(message, aes_key)
                    print("\n" + decrypted_msg)
                except UnicodeDecodeError as e:
                    print(f"{Fore.YELLOW}[!] Decryption Unicode Decode Error: {e}")
                    continue
        except Exception as e:
            print(f"{Fore.RED}[!!] Error: {e}{Fore.RESET}")
            break


threading.Thread(target=listen, daemon=True).start()

while True:
    sending = input()
    if sending.lower() == 'q':
        break
    if aes_key is None:
        print(f"{Fore.RED}[!!] AES key not set up yet. Please wait.{Fore.RESET}")
        continue
    date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    to_send = f"{uCOLOR}[{date_now}] {name}: {sending}{Fore.RESET}"
    encrypted_message = aes_encrypt(to_send, aes_key)
    tcp.send(encrypted_message)

disconnect_msg = f"{uCOLOR}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {name} has disconnected.{Fore.RESET}"
encrypted_disconnect_msg = aes_encrypt(disconnect_msg, aes_key)
tcp.send(encrypted_disconnect_msg)

tcp.close()
print(f"{Fore.RED}[!!] Connection Closed{Fore.RESET}")
