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


server_public, server_private = rsa.newkeys(1024)
client_keys = {}  # Dictionary to store public keys


# Initiate Client Sockets
cSOCKETS = set()
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP Socket
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Set Socket to be Reusable
tcp.bind((sHOST, sPORT))  # Bind Socket to Server
tcp.listen(5)  # Only 5 Connection can queue at once
print(f"{Fore.GREEN}[*] Live on {sHOST}:{sPORT} {Fore.RESET}")  # Print Socket Connection Info


# Function to broadcast messages to all clients
def broadcast(message):
    for clientSOCKET in cSOCKETS:
        client_public_key = client_keys[clientSOCKET]
        encrypted_msg = rsa.encrypt(message.encode(), client_public_key)
        clientSOCKET.send(encrypted_msg)


# Function to Listen for Client Connections
def client_connect(cSOCKET):
    while True:
        try:
            message = cSOCKET.recv(4096)  # Adjust buffer size as needed
            decrypted_msg = rsa.decrypt(message, server_private).decode()
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
        client_public_key_data = cSOCKET.recv(4096)  # Receive client's public key
        client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_data)
        client_keys[cSOCKET] = client_public_key
        cSOCKET.send(server_public.save_pkcs1('PEM'))  # Send server's public key to the client
        threading.Thread(target=client_connect, args=(cSOCKET,), daemon=True).start()
except KeyboardInterrupt:
    print(f"{Fore.Yellow}[*] Server shutting down...{Fore.RESET}")
finally:
    for client in cSOCKETS:
        client.close()
    tcp.close()
