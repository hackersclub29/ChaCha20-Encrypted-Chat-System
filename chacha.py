import secrets
import hashlib

def generate_chacha_key():
    # Generate a secure random 256-bit (32-byte) key
    random_bytes = secrets.token_bytes(32)  # 32 bytes for 256 bits
    return random_bytes.hex()

def generate_chacha_nonce():
    # Generate a secure random 96-bit (12-byte) nonce
    random_bytes = secrets.token_bytes(12)  # 12 bytes for 96 bits
    return random_bytes.hex()

def main():
    for i in range(10):  # Generate 10 pairs
        chacha_key = generate_chacha_key()
        chacha_nonce = generate_chacha_nonce()
        print(f"ChaChaKey: {chacha_key}")
        print(f"ChaChaNonce: {chacha_nonce}")
        print("-" * 50)

if __name__ == "__main__":
    main()
