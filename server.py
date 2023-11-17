import base64
import socket
import threading
import rsa
from colorama import Fore, init

init()  # Colorama initialization

# Server Connection Info
sHOST = '0.0.0.0'  # Listen on all network interfaces
sPORT = 2003

print(f"{Fore.YELLOW}[*] Creating RSA Keys for Secure Communication... please wait{Fore.RESET}")
server_public, server_private = rsa.newkeys(2048)
print(f"{Fore.GREEN}[*] Key successfully generated!")

client_keys = {}  # Dictionary to store public keys of clients
cSOCKETS = set()  # Set to store client sockets
first_client = None  # Reference to the first client

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind((sHOST, sPORT))
tcp.listen(5)
print(f"{Fore.GREEN}[*] Live on {sHOST}:{sPORT}{Fore.RESET}")


def broadcast(message):
    for clientSOCKET in cSOCKETS:
        try:
            clientSOCKET.send(message)
        except Exception as e:
            print(f"{Fore.RED}[!] Error sending to client: {e} {Fore.RESET}")


def client_connect(cSOCKET, uADDRESS):
    global first_client
    while True:
        try:
            message = cSOCKET.recv(8192)
            if message:
                broadcast(message)
            else:
                break  # Client disconnected
        except Exception as e:
            print(f"{Fore.RED}[!] Error with client {uADDRESS}: {e} {Fore.RESET}")
            break
    cSOCKETS.remove(cSOCKET)
    cSOCKET.close()
    print(f"{Fore.YELLOW}[!] Client {uADDRESS} disconnected.{Fore.RESET}")


try:
    while True:
        cSOCKET, uADDRESS = tcp.accept()
        print(f"{Fore.GREEN}[+] {uADDRESS} connected {Fore.RESET}")
        cSOCKETS.add(cSOCKET)
        cSOCKET.send(server_public.save_pkcs1('PEM'))
        print(f"{Fore.GREEN}[*] Server Public Key Sent to: {uADDRESS}{Fore.RESET}")

        client_public_key_data = cSOCKET.recv(8192)
        client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_data)
        client_keys[uADDRESS] = client_public_key
        print(f"{Fore.GREEN}[*] Client Public Key Received from: {uADDRESS}{Fore.RESET}")

        if not first_client:
            first_client = cSOCKET
            first_client.send(b"FIRST")
            print(f"{Fore.YELLOW}[!] First client set: {uADDRESS}{Fore.RESET}")
        else:
            encoded_client_public_key = base64.b64encode(client_public_key_data)
            first_client.send(f"NEW_USER#{uADDRESS}#{encoded_client_public_key.decode()}".encode())

        threading.Thread(target=client_connect, args=(cSOCKET, uADDRESS), daemon=True).start()
except KeyboardInterrupt:
    print(f"{Fore.YELLOW}[*] Server shutting down...{Fore.RESET}")
finally:
    for client in cSOCKETS:
        client.close()
    tcp.close()
    print(f"{Fore.RED}[*] Server shut down{Fore.RESET}")
