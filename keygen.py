import os
from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

def generate_keys(directory, name, email):
    try:
        # Ensure the directory exists
        os.makedirs(directory, exist_ok=True)

        # Generate a new RSA key pair
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)

        # Create a new User ID
        uid = PGPUID.new(name, email=email)

        # Add User ID to the key with preferences
        key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],  # Only AES256 now
            compression=[CompressionAlgorithm.ZLIB]
        )

        # Save private key
        private_key_path = os.path.join(directory, "private_key.asc")
        with open(private_key_path, "w") as private_key_file:
            private_key_file.write(str(key))

        # Save public key
        public_key_path = os.path.join(directory, "public_key.asc")
        with open(public_key_path, "w") as public_key_file:
            public_key_file.write(str(key.pubkey))

        print(f"Keys generated successfully!")
        print(f"Private Key: {private_key_path}")
        print(f"Public Key: {public_key_path}")

    except Exception as e:
        print(f"Error generating keys: {e}")

if __name__ == "__main__":
    directory = input("Enter the directory to save the keys: ").strip()
    name = input("Enter your name: ").strip()
    email = input("Enter your email: ").strip()
    generate_keys(directory, name, email)
