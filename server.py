import socket
import threading
import rsa
from colorama import Fore, init


init()  # Colorama
colors = [Fore.BLUE, Fore.LIGHTBLUE_EX, Fore.CYAN, Fore.LIGHTCYAN_EX,
          Fore.GREEN, Fore.LIGHTGREEN_EX, Fore.RED, Fore.LIGHTRED_EX,
          Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.YELLOW, Fore.LIGHTYELLOW_EX,
          Fore.WHITE]

# Server Connection Info
sHOST = socket.gethostbyname(socket.gethostname())
sPORT = 2003

# Open RSA Keys // Set up functions
with open("server_public.pem", "rb") as f:
    server_public = rsa.PublicKey.load_pkcs1(f.read())

with open("server_private.pem", "rb") as f:
    server_private = rsa.PrivateKey.load_pkcs1(f.read())

with open("client_public.pem", "rb") as f:
    client_public = rsa.PublicKey.load_pkcs1(f.read())


def encryption_to_client(message):
    if isinstance(message, str):
        message = message.encode()
    return rsa.encrypt(message, client_public)


def decryption_from_client(message):
    print(message)
    decrypted_msg = rsa.decrypt(message, server_private)
    return decrypted_msg.decode()


# Initiate Client Sockets
cSOCKETS = set()
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP Socket
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Set Socket to be Reusable
tcp.bind((sHOST, sPORT))  # Bind Socket to Server
tcp.listen(5)  # Only 5 Connection can queue at once
print(f"{Fore.GREEN}[*] Live on {sHOST}:{sPORT} {Fore.RESET}")  # Print Socket Connection Info


# Function to Listen for Client Connections
def client_connect(cSOCKET):
    while True:
        try:
            message = cSOCKET.recv(1024)  # Adjust buffer size as needed
            decrypted_msg = decryption_from_client(message)
        except Exception as e: # Error Handling
            print(f"{Fore.RED}[!] Error: {e} {Fore.RESET}")
            cSOCKETS.remove(cSOCKET)  # Remove bad clients
        for clientSOCKET in cSOCKETS:  # For loop to send message to all connected users
            clientSOCKET.send(encryption_to_client(decrypted_msg))  # Send Message


try:
    while True:
        cSOCKET, uADDRESS = tcp.accept()
        print(f"{Fore.GREEN}[+] {uADDRESS} connected. {Fore.RESET}")
        cSOCKETS.add(cSOCKET)
        threading.Thread(target=client_connect, args=(cSOCKET,), daemon=True).start()
except KeyboardInterrupt:
    print(f"{Fore.Yellow}[*] Server shutting down...{Fore.RESET}")
finally:
    for client in cSOCKETS:
        client.close()
    tcp.close()
