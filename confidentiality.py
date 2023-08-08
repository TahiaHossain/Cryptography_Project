from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def write_key(key, key_filename):
    with open(key_filename, "wb") as key_file:
        key_file.write(key)

def load_key(key_filename):
    with open(key_filename, "rb") as key_file:
        return key_file.read()

def encrypt_file(key, input_filename, output_filename):
    cipher = Fernet(key)
    with open(input_filename, "rb") as input_file:
        plaintext = input_file.read()
    encrypted_data = cipher.encrypt(plaintext)
    with open(output_filename, "wb") as output_file:
        output_file.write(encrypted_data)

def decrypt_file(key, input_filename, output_filename):
    cipher = Fernet(key)
    with open(input_filename, "rb") as input_file:
        encrypted_data = input_file.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    with open(output_filename, "wb") as output_file:
        output_file.write(decrypted_data)

def main():
    key_filename = "encryption_key.key"
    input_filename = "secret.txt"
    encrypted_filename = "encrypted.txt"
    decrypted_filename = "decrypted.txt"

    # Generate a new key and save it to a file
    key = generate_key()
    write_key(key, key_filename)

    # ask = input("Encrypt or Decrypt? Type 1 for Ecryption and 2 for Decryption. ")
    
    # Encrypt the input file

    # if ask == 1 :
    encrypt_file(key, input_filename, encrypted_filename)

    # Decrypt the encrypted file

    # if ask == 2 :
    decrypt_file(key, encrypted_filename, decrypted_filename)
    # else :
    # print("Invalid Command. Try again with 1 or 2")

if __name__ == "__main__" :
    main()