from pgpy import PGPKey, PGPMessage
import base64


def encrypt_data(plaintext, public_key_path):
    try:
        # Load the public key directly from its path
        public_key, _ = PGPKey.from_file(public_key_path)

        # Create a PGPMessage
        message = PGPMessage.new(plaintext)

        # Encrypt the message using the public key
        encrypted_message = public_key.encrypt(message)

        # Return the encrypted message in base64 format
        return base64.b64encode(bytes(encrypted_message)).decode()
    
    except Exception as e:
        print(f"Error encrypting data: {e}")
    return None


def save_encrypted_data(encrypted_data, output_file):
    try:
        with open(output_file, "w") as file:
            file.write(encrypted_data)
        print(f"Encrypted data saved to {output_file}")
    except Exception as e:
        print(f"Error saving encrypted data: {e}")


def main():
    print("ChaCha20 Encryption Configuration")
    
    # Request a 32-byte (64 hex characters) key from the user
    while True:
        key = input("Enter a 32-byte (64 hex characters) key: ").strip()
        if len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
            break
        print("Invalid key. Please enter a valid 64-character hexadecimal string.")

    # Request a 12-byte (24 hex characters) nonce from the user
    while True:
        nonce = input("Enter a 12-byte (24 hex characters) nonce: ").strip()
        if len(nonce) == 24 and all(c in "0123456789abcdefABCDEF" for c in nonce):
            break
        print("Invalid nonce. Please enter a valid 24-character hexadecimal string.")

    # Concatenate the key and nonce
    data_to_encrypt = key + nonce

    # Ask for the public key path
    public_key_path = input("Enter the path to the public key (e.g., /path/to/public.key): ").strip()

    # Suggest hosting the public key
    print("You should host your public key on a network or internet for sharing. For example, upload it to:")
    print("http://example.com/yourfilename.txt")
    
    # Ask the user for the filename to save the encrypted data
    output_file = input("Enter the filename to save the encrypted data (e.g., encrypted_data.txt): ").strip()

    # Encrypt the data
    encrypted_data = encrypt_data(data_to_encrypt, public_key_path)
    if encrypted_data:
        # Save the encrypted data to the specified file
        save_encrypted_data(encrypted_data, output_file)


if __name__ == "__main__":
    main()
