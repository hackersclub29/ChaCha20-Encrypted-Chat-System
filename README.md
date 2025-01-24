Secure Peer-to-Peer Networking with ChaCha20 Encryption
This repository provides a Python-based implementation of a secure peer-to-peer (P2P) communication system. The system uses ChaCha20 encryption for secure message exchange and supports reconnection mechanisms, file encryption/decryption, and decentralized networking without relying on a central server.

Key Features
ChaCha20 Encryption: Ensures robust and efficient encryption for secure communication.
Public-Key Integration: Decrypt ChaCha20 keys and nonces securely using PGP private keys.
Peer-to-Peer Networking: Direct communication without centralized servers.
Reconnection Support: Automatically attempts to reconnect in case of a connection loss.
Port Forwarding Options: Utilize tools like ngrok or playit.gg to enable external access.
Interactive Console: User-friendly interface with color-coded error and success messages.
Prerequisites
Python installed on your system.
Required Python modules from requirements.txt:
bash
Copy
Edit
pip install -r requirements.txt
How to Use
1. Prepare Your Environment
Install Python and ensure the required modules are installed.
Obtain the PGP private key for decrypting ChaCha20 key and nonce.
2. Host or Join Secure Communication
Download the Encrypted Key File:
Provide the URL to download the ChaCha20 encrypted key and nonce.

Decrypt the Key:
Use your PGP private key to decrypt the downloaded file.

Choose Your Role:

Server Mode: Host the server to accept incoming connections.
Client Mode: Connect to a peer's server.
Provide Connection Details:

Server IP and port.
Usernames for both participants.
Example Workflow
Start the Application:
bash
Copy
Edit
python main.py
Enter the URL for the encrypted key file and your private key path.
Decrypt the ChaCha20 key and nonce.
Choose your role:
To host: Enter server.
To connect: Enter client.
Provide the required details (IP, port, and username).
Start sending and receiving encrypted messages.
Notes
Security: Always exchange public keys securely to prevent unauthorized access.
Port Forwarding: Use tools like ngrok or playit.gg to make your server accessible over the internet.
Reconnection: The system will automatically attempt to reconnect if the connection is lost.
