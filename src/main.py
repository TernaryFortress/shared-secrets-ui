import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class KeyExchangeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Shared-Secret Key Exchange")
        
        # Generate ECC Keypair on button press
        self.private_key = None
        
        # UI Components
        self.create_widgets()

    def create_widgets(self):
        # Your Public Key Field
        tk.Label(self.root, text="Your Public Key:").grid(row=0, column=0, sticky='w')
        self.public_key_field = tk.Entry(self.root, width=50, state="readonly")
        self.public_key_field.grid(row=0, column=1, padx=10)
        
        # Generate Button
        generate_btn = tk.Button(self.root, text="Generate", command=self.generate_keypair)
        generate_btn.grid(row=0, column=2, padx=10)

        # Friend's Public Key Field
        tk.Label(self.root, text="Friend's Public Key:").grid(row=1, column=0, sticky='w')
        self.friend_pub_key_field = tk.Entry(self.root, width=50)
        self.friend_pub_key_field.grid(row=1, column=1, padx=10)

        # Instructions
        tk.Label(self.root, text="Exchange public keys with your friend").grid(row=2, column=0, columnspan=3, pady=10)

        # Radio Buttons and Text Fields
        self.option = tk.StringVar(value="encrypt")
        tk.Radiobutton(self.root, text="Text to encrypt", variable=self.option, value="encrypt").grid(row=3, column=0, sticky='w')
        self.text_to_encrypt = tk.Entry(self.root, width=50)
        self.text_to_encrypt.grid(row=3, column=1, padx=10)

        tk.Radiobutton(self.root, text="Text to decrypt", variable=self.option, value="decrypt").grid(row=4, column=0, sticky='w')
        self.text_to_decrypt = tk.Entry(self.root, width=50)
        self.text_to_decrypt.grid(row=4, column=1, padx=10)

        # Output Field
        tk.Label(self.root, text="Output:").grid(row=5, column=0, sticky='w')
        self.output_field = tk.Entry(self.root, width=50, state="readonly")
        self.output_field.grid(row=5, column=1, padx=10)

        # Submit Button
        submit_btn = tk.Button(self.root, text="Submit", command=self.submit)
        submit_btn.grid(row=6, column=0, columnspan=3, pady=10)

    def generate_keypair(self):
        # Generate ECC Keypair
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = self.private_key.public_key()

        # Serialize public key to bytes
        pub_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pub_key_str = pub_key_bytes.decode('utf-8')

        # Display the public key
        self.public_key_field.config(state="normal")
        self.public_key_field.delete(0, tk.END)
        self.public_key_field.insert(0, pub_key_str.strip())
        self.public_key_field.config(state="readonly")

    def submit(self):
        if not self.private_key:
            messagebox.showerror("Error", "Please generate your keypair first.")
            return

        friend_pub_key_str = self.friend_pub_key_field.get().strip()
        if not friend_pub_key_str:
            messagebox.showerror("Error", "Please enter your friend's public key.")
            return

        # Deserialize friend's public key
        try:
            friend_public_key = serialization.load_pem_public_key(friend_pub_key_str.encode('utf-8'), backend=default_backend())
        except ValueError:
            messagebox.showerror("Error", "Invalid friend's public key format.")
            return

        # Generate shared secret
        shared_key = self.private_key.exchange(ec.ECDH(), friend_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)

        # Get input text
        if self.option.get() == "encrypt":
            plaintext = self.text_to_encrypt.get().strip().encode('utf-8')
            if not plaintext:
                messagebox.showerror("Error", "Please enter text to encrypt.")
                return
            # Encrypt
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            encrypted_message = iv + encryptor.tag + ciphertext

            # Output result
            self.output_field.config(state="normal")
            self.output_field.delete(0, tk.END)
            self.output_field.insert(0, encrypted_message.hex())
            self.output_field.config(state="readonly")

        elif self.option.get() == "decrypt":
            encrypted_message_hex = self.text_to_decrypt.get().strip()
            if not encrypted_message_hex:
                messagebox.showerror("Error", "Please enter text to decrypt.")
                return
            try:
                encrypted_message = bytes.fromhex(encrypted_message_hex)
                iv, tag, ciphertext = encrypted_message[:12], encrypted_message[12:28], encrypted_message[28:]
                
                # Decrypt
                cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                # Output result
                self.output_field.config(state="normal")
                self.output_field.delete(0, tk.END)
                self.output_field.insert(0, plaintext.decode('utf-8'))
                self.output_field.config(state="readonly")

            except Exception as e:
                messagebox.showerror("Error", "Decryption failed.")
                return

# Initialize the GUI# Main function
def main():
    root = tk.Tk()
    app = KeyExchangeApp(root)
    root.mainloop()

# main() check
if __name__ == "__main__":
    main()