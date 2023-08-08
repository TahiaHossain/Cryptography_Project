import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.fernet import InvalidToken
import confidentiality
from cia import *
import os

def show_decrypted_message(decrypted_message):
    message_window = tk.Toplevel(root)
    message_window.title("Decrypted Message")

    message_label = tk.Label(message_window, text=decrypted_message, font=("Segoe UI Emoji", 12))
    message_label.pack(padx=10, pady=10)

def get_matching_password():
    while True:
        password = simpledialog.askstring("Password", "Enter a password:")
        confirm_password = simpledialog.askstring("Confirm Password", "Confirm the password:")
        
        if password == confirm_password:
            return password
        else:
            messagebox.showerror("Error", "Passwords didn't match. Try again.")

def encrypt_button_click():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if file_path:
        password = get_matching_password()
        print("Encrypting:", file_path)
        if password:
            confirm = messagebox.askyesno("Confirmation", "The original file will be deleted and replaced with the encrypted file. Continue?")
            if confirm:
                confidentiality.encrypt_file(password, file_path)
                messagebox.showinfo("Success", "File encrypted successfully.")
                os.remove(file_path)

def decrypt_button_click():
    file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if file_path:
        password = simpledialog.askstring("Password", "Enter a password:")
        try:
            decrypted_message = confidentiality.decrypt_file(password, file_path, write_the_output=False)
            show_decrypted_message(decrypted_message)
        except InvalidToken:
            messagebox.showerror("Error", "Wrong password.")

def generate_key_pair_button_click():
    private_key, public_key = generate_key_pair()

    private_key_filename = filedialog.asksaveasfilename(title="Save Private Key", defaultextension=".pem")
    public_key_filename = filedialog.asksaveasfilename(title="Save Public Key", defaultextension=".pem") if private_key_filename else None

    save_private_key(private_key, private_key_filename)
    save_public_key(public_key, public_key_filename)
    messagebox.showinfo("Success", "Key pair generated and stored successfully.")
    
def sign_button_click():
    file_path = filedialog.askopenfilename(title="Select a file to sign")
    private_key_filename = filedialog.askopenfilename(title="Select a private key") if file_path else None

    private_key = load_private_key(private_key_filename)
    signature = sign_data(private_key, file_path)
    
    # Save the signature to a file
    signature_filename = filedialog.asksaveasfilename(title="Save Signature", defaultextension=".sig")
    with open(signature_filename, "wb") as file:
        file.write(signature)
    messagebox.showinfo("Success", "Signature generated and stored successfully.")

def verify_signature_button_click():
    file_path = filedialog.askopenfilename(title="Select a file to verify")
    public_key_filename = filedialog.askopenfilename(title="Select a public key") if file_path else None
    signature_filename = filedialog.askopenfilename(title="Select a signature to verify") if public_key_filename else None

    public_key = load_public_key(public_key_filename)
    signature = read_from_file(signature_filename)

    if verify_signature(public_key, signature, file_path):
        messagebox.showinfo("Success", "Signature is valid.")
    else:
        messagebox.showerror("Error", "Signature is invalid.")

# Create the main window
root = tk.Tk()
root.title("File Encryption/Decryption")

# Create buttons for encryption and decryption
encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_button_click)
decrypt_button = tk.Button(root, text="Decrypt and read", command=decrypt_button_click)
generate_key_pair_button = tk.Button(root, text="Generate Key Pair", command=generate_key_pair_button_click)
sign_file_button = tk.Button(root, text="Sign File", command=sign_button_click)
verify_signature_button = tk.Button(root, text="Verify Signature", command=verify_signature_button_click)

encrypt_button.config(height=5, width=20, bg="light blue")
decrypt_button.config(height=5, width=20, bg="light blue")
generate_key_pair_button.config(height=5, width=20, bg="light blue")
sign_file_button.config(height=5, width=20, bg="light blue")
verify_signature_button.config(height=5, width=20, bg="blue")

encrypt_button.grid(row=0, column=0, padx=(100,10), pady=(100,10))
decrypt_button.grid(row=0, column=1, padx=(10,100), pady=(100,10))
sign_file_button.grid(row=1, column=0, padx=(100,10), pady=10)
verify_signature_button.grid(row=1, column=1, padx=(10,100), pady=10)
generate_key_pair_button.grid(row=2, column=0, padx=(100, 10), pady=(10,100))

# Start the GUI event loop
root.mainloop()
