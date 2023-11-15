import socket
import random
import threading
import rsa
from datetime import datetime
from colorama import Fore, init
from keys import create_keys

init()  # Colorama
colors = [Fore.BLUE, Fore.LIGHTBLUE_EX, Fore.CYAN, Fore.LIGHTCYAN_EX,
          Fore.GREEN, Fore.LIGHTGREEN_EX, Fore.RED, Fore.LIGHTRED_EX,
          Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.YELLOW, Fore.LIGHTYELLOW_EX,
          Fore.WHITE]

uCOLOR = random.choice(colors)  # Picks random color for each client

sHOST = "192.168.146.1"  # Server IP
sPORT = 2003  # Server Port
sep = "<SEP>"

# Open RSA Keys
with open("client_public.pem", "rb") as f:
    client_public = rsa.PublicKey.load_pkcs1(f.read())

with open("client_private.pem", "rb") as f:
    client_private = rsa.PrivateKey.load_pkcs1(f.read())

with open("server_public.pem", "rb") as f:
    server_public = rsa.PublicKey.load_pkcs1(f.read())


tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Initialize TCP socket
print(f"{Fore.YELLOW}[*] Connecting to {sHOST}:{sPORT}...{Fore.RESET}")  # Return status

tcp.connect((sHOST, sPORT))  # Connect to server
print(f"{Fore.GREEN}[+] Connected {Fore.RESET}")  # Return status

name = input("Enter your name: ")  # Client inputs username


def listen():  # Function to listen for messages
    while True:
        try:
            message = tcp.recv(1024)  # When message is received
            decrypted_msg = rsa.decrypt(message, client_private).decode('utf-8')  # Decrypt Message
            print("\n" + decrypted_msg)  # Print message
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Fore.RESET}")
            break  # Break if error occurs


threading.Thread(target=listen, daemon=True).start()  # Listen for messages always, Daemon ends thread when last thread ends


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
