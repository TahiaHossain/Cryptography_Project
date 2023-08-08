from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from os import urandom
from base64 import urlsafe_b64encode
    
def write_to_file(content, filename):
    with open(filename, "wb") as key_file:
        key_file.write(content)

def read_from_file(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

def generate_salt():
    print("Generating salt...")
    salt = urandom(16) # Generate a random 16-byte salt
    write_to_file(salt, "salts/salt.txt")
    return salt  

def generate_key_from_password(password, salt = None):
    if not salt:
        salt = generate_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32  # Length of the derived key
    )
    key = urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(password, input_filename):
    password = password.encode()  # Convert to bytes

    key = generate_key_from_password(password)
    
    cipher = Fernet(key)
    with open(input_filename, "rb") as input_file:
        plaintext = input_file.read()
    encrypted_data = cipher.encrypt(plaintext)
    with open('encrypted.txt', "wb") as output_file:
        output_file.write(encrypted_data)

def decrypt_file(password, input_filename, output_filename='decrypted.txt',  salt='salts/salt.txt', write_the_output = True):
    password = password.encode() 
    salt = read_from_file(salt)
    key = generate_key_from_password(password, salt=salt)
    cipher = Fernet(key)

    with open(input_filename, "rb") as input_file:
        encrypted_data = input_file.read()
        
    decrypted_data = cipher.decrypt(encrypted_data)
    
    if write_the_output:
        with open(output_filename, "wb") as output_file:
            output_file.write(decrypted_data)
        return output_filename
    else:
        return decrypted_data

def main():
    input_filename = "secret.txt"
    encrypted_filename = "encrypted.txt"

    # Generate a new key and save it to a file
    
    # Encrypt the input file
    password = input("Enter a password: ")
    
    # encrypt_file(password, input_filename)

    # Decrypt the encrypted file

    # if ask == 2 :
    decrypt_file(password, encrypted_filename)
    # else :
    # print("Invalid Command. Try again with 1 or 2")

if __name__ == "__main__" :
    main()