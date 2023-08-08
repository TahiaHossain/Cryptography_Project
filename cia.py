import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from confidentiality import *

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(filename, "wb") as key_file:
        key_file.write(pem)

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(filename, "wb") as key_file:
        key_file.write(pem)

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        pem_data = key_file.read()
        return serialization.load_pem_private_key(pem_data, password=None)

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        pem_data = key_file.read()
        return serialization.load_pem_public_key(pem_data)

def sign_data(private_key, input_filename):
    original_hash = calculate_hash(input_filename)
    
    return private_key.sign(
        original_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

def verify_signature(public_key, signature, decrypted_filename):
    decrypted_hash = calculate_hash(decrypted_filename)
    try:
        public_key.verify(
            signature,
            decrypted_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except:
        return False

def calculate_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            data = file.read(65536)  # Read the file in chunks of 64KB
            if not data:
                break
            hasher.update(data)
    return hasher.digest()

def main():
    key_filename = "encryption_key.key"
    private_key_filename = "private_key.pem"
    public_key_filename = "public_key.pem"
    input_filename = "secret.txt"
    encrypted_filename = "encrypted.txt"
    decrypted_filename = "secret.txt"

    # Generate a new encryption key pair and save them to files
    private_key, public_key = generate_key_pair()
    save_private_key(private_key, private_key_filename)
    save_public_key(public_key, public_key_filename)

    # Encrypt the input file
    # symmetric_key = Fernet.generate_key()
    # encrypt_file(symmetric_key, input_filename, encrypted_filename)

    # Decrypt the encrypted file
    # decrypt_file(symmetric_key, encrypted_filename, decrypted_filename)

    # Load private key and sign the hash
    private_key = load_private_key(private_key_filename)
    signature = sign_data(private_key, input_filename)

    # Verify the signature and integrity of the decrypted file
    public_key = load_public_key(public_key_filename)
    is_signature_valid = verify_signature(public_key, signature, decrypted_filename)

    if is_signature_valid:
        print("File integrity and authenticity verified successfully.")
    else:
        print("WARNING: File integrity or authenticity verification failed!")

if __name__ == "__main__":
    print("----PROGRAM STARTED----")
    main()
