import base64
import socket
import threading
import warnings
import requests
import pyreadline  # To improve input handling
import time
from pgpy import PGPKey, PGPMessage
from Crypto.Cipher import ChaCha20
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Redline Error Messages with Color
def print_error(message):
    print(Fore.RED + Style.BRIGHT + "[ERROR] " + message)

def print_info(message):
    print(Fore.YELLOW + "[INFO] " + message)

def print_success(message):
    print(Fore.GREEN + "[SUCCESS] " + message)

# Function to set the username
def set_username():
    username = input("Enter your username: ").strip()
    return username

# Decrypt PGP data to get ChaCha20 key and nonce
def decrypt_data(encrypted_data, private_key_path):
    try:
        private_key, _ = PGPKey.from_file(private_key_path)
        encrypted_message = PGPMessage.from_blob(base64.b64decode(encrypted_data))
        decrypted_message = private_key.decrypt(encrypted_message).message
        return decrypted_message
    except Exception as e:
        print_error(f"Decryption failed: {e}")
    return None

# Download encrypted file from URL
def download_encrypted_data(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            print_error(f"Failed to download file. Status code: {response.status_code}")
    except Exception as e:
        print_error(f"Downloading file failed: {e}")
    return None

# Encrypt message using ChaCha20
def encrypt_message(message, key, nonce):
    try:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted_message = cipher.encrypt(message.encode('utf-8'))
        return encrypted_message
    except Exception as e:
        print_error(f"Encryption failed: {e}")
    return None

# Decrypt message using ChaCha20
def decrypt_message(encrypted_message, key, nonce):
    try:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        decrypted_message = cipher.decrypt(encrypted_message)
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print_error(f"Decryption failed: {e}")
    return None

# Handle receiving messages (runs on a separate thread)
def receive_messages(conn, key, nonce, username, peer_name):
    try:
        while True:
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                print_info(f"You lost connection with {peer_name}. Reconnecting in 10 seconds...")
                time.sleep(10)  # Reconnect after 10 seconds
                break
            decrypted_message = decrypt_message(encrypted_message, key, nonce)
            print(f"\n[{peer_name}] {decrypted_message}")
    except Exception as e:
        print_error(f"Receiving message failed: {e}")
        print_info(f"You lost connection with {peer_name}. Reconnecting in 10 seconds...")
        time.sleep(10)  # Reconnect after 10 seconds

# Reconnection logic for client
def reconnect_to_server(host, port, key, nonce, username):
    while True:
        try:
            print_info(f"Trying to reconnect to the server at {host}:{port}...")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            print_success(f"Connected to server at {host}:{port} as {username}")
            
            # Start a thread to handle receiving messages
            threading.Thread(target=receive_messages, args=(client_socket, key, nonce, username, "Server"), daemon=True).start()

            # Handle sending messages
            while True:
                try:
                    message = input(f"\n[{username}] You: ")
                    if message.strip():
                        encrypted_message = encrypt_message(message, key, nonce)
                        client_socket.sendall(encrypted_message)
                    else:
                        print("Please enter a message.")
                except Exception as e:
                    print_error(f"Error sending message: {e}")
                    break
        except Exception as e:
            print_error(f"Connection failed: {e}")
            time.sleep(10)  # Wait 10 seconds before retrying

# Reconnection logic for server
def start_server(host, port, key, nonce, username):
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            try:
                server_socket.bind((host, port))
                server_socket.listen(1)
                print_info(f"Server listening on {host}:{port}...")
                
                conn, addr = server_socket.accept()
                print_success(f"Connected to {addr} as {username}")

                # Start a thread to handle receiving messages
                threading.Thread(target=receive_messages, args=(conn, key, nonce, username, "Client"), daemon=True).start()

                # Handle sending messages
                while True:
                    try:
                        message = input(f"\n[{username}] You: ")
                        if message.strip():
                            encrypted_message = encrypt_message(message, key, nonce)
                            conn.sendall(encrypted_message)
                        else:
                            print("Please enter a message.")
                    except Exception as e:
                        print_error(f"Error sending message: {e}")
                        break
            except Exception as e:
                print_error(f"Server error: {e}")
                time.sleep(10)  # Wait 10 seconds before retrying

def main():
    # Get ChaCha20 key and nonce from the encrypted file URL
    encrypted_file_url = input("Enter the URL of the encrypted file: ").strip()
    private_key_path = input("Enter the path to the private key: ").strip()

    # Download encrypted data
    encrypted_data = download_encrypted_data(encrypted_file_url)
    if not encrypted_data:
        print_error("Failed to download encrypted data. Exiting.")
        return

    # Decrypt data
    decrypted_data = decrypt_data(encrypted_data, private_key_path)
    if decrypted_data:
        # Extract ChaCha20 key and nonce
        key = bytes.fromhex(decrypted_data[:64])  # First 32 bytes (64 hex characters)
        nonce = bytes.fromhex(decrypted_data[64:64+24])  # Next 12 bytes (24 hex characters)
        
        print_success(f"ChaCha20 Key: {key.hex()}")
        print_success(f"ChaCha20 Nonce: {nonce.hex()}")
        
        # Ask both users for usernames
        username = set_username()

        # Get choice for server/client mode
        mode = input("Enter 'server' to start the server, 'client' to connect as client: ").strip().lower()
        host = input("Enter the peer's IP address: ").strip()
        try:
            port = int(input("Enter the port to use (e.g., 5000): ").strip())
        except ValueError:
            print_error("Invalid port number. Exiting.")
            return
        
        if mode == 'server':
            start_server(host, port, key, nonce, username)
        elif mode == 'client':
            reconnect_to_server(host, port, key, nonce, username)
        else:
            print_error("Invalid mode selected. Exiting.")
    else:
        print_error("Failed to decrypt data.")

if __name__ == "__main__":
    main()
