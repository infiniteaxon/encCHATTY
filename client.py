import socket
import random
import threading
import rsa
from datetime import datetime
from colorama import Fore, init

init()  # Colorama
colors = [Fore.BLUE, Fore.LIGHTBLUE_EX, Fore.CYAN, Fore.LIGHTCYAN_EX,
          Fore.GREEN, Fore.LIGHTGREEN_EX, Fore.RED, Fore.LIGHTRED_EX,
          Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.YELLOW, Fore.LIGHTYELLOW_EX,
          Fore.WHITE]

uCOLOR = random.choice(colors)  # Picks random color for each client

sHOST = "192.168.146.1"  # Server IP
sPORT = 2003  # Server Port
sep = "<SEP>"

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Initialize TCP socket
print(f"{Fore.YELLOW}[*] Connecting to {sHOST}:{sPORT}...{Fore.RESET}")  # Return status

tcp.connect((sHOST, sPORT))  # Connect to server
print(f"{Fore.GREEN}[+] Connected {Fore.RESET}")  # Return status

name = input("Enter your name: ")  # Client inputs username


# Create Keys and Open Them
def create_keys_client():
    client_public, client_private = rsa.newkeys(1024)
    return client_public, client_private


# Main key handling function
def use_keys():
    client_public, client_private = create_keys_client()
    tcp.send(client_public.save_pkcs1('PEM'))  # Send the public key to the server right after establishing a connection
    server_public_key_data = tcp.recv(4096)  # Assuming the next message from the server will be its public key
    server_public = rsa.PublicKey.load_pkcs1(server_public_key_data)

    return client_public, client_private, server_public


client_public, client_private, server_public = use_keys()


def listen(client_private_key):  # Function to listen for messages
    while True:
        try:
            message = tcp.recv(4096)  # When message is received
            decrypted_msg = rsa.decrypt(message, client_private_key).decode('utf-8')  # Decrypt Message
            print("\n" + decrypted_msg)  # Print message
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Fore.RESET}")
            break  # Break if error occurs


threading.Thread(target=listen, args=(client_private,), daemon=True).start()  # Listen for messages always, Daemon ends thread when last thread ends

while True:
    sending = input()  # Message being sent
    if sending.lower() == 'q':  # Exit the program
        break
    date_now = datetime.now().strftime('%m-%d-%Y %H:%M:%S')  # Find current date/time
    to_send = f"{uCOLOR}[{date_now}] {name}: {sending}{Fore.RESET}"  # Structure message
    encrypted_msg = rsa.encrypt(to_send.encode('utf-8'), server_public)
    tcp.send(encrypted_msg)  # Send Message

tcp.close()  # Close socket
print("{Fore.RED}[!] Connection Closed ")
