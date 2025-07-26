import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import zlib

def generate_key_from_password(password):
    salt = b"unique_salt_value"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_image(image_path, password):
    with open(image_path, "rb") as image_file:
        image_data = image_file.read()
    
    key = generate_key_from_password(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padding_length = 16 - len(image_data) % 16
    padded_data = image_data + bytes([padding_length]) * padding_length
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    compressed_data = zlib.compress(encrypted_data)

    # Ask the user where to save the encrypted file
    encrypted_image_path = filedialog.asksaveasfilename(
        defaultextension=".bin",
        filetypes=[("Encrypted Files", "*.bin")],
        title="Save Encrypted Image"
    )

    if not encrypted_image_path:
        return
    
    with open(encrypted_image_path, "wb") as enc_file:
        enc_file.write(iv + compressed_data)
    
    messagebox.showinfo("Success", f"Image encrypted successfully!\nSaved as: {encrypted_image_path}")

def decrypt_image(encrypted_image_path, password):
    with open(encrypted_image_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    
    decompressed_data = zlib.decompress(encrypted_data)
    
    key = generate_key_from_password(password)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(decompressed_data) + decryptor.finalize()
    
    padding_length = decrypted_data[-1]
    original_data = decrypted_data[:-padding_length]
    
    decrypted_image_path = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG Image", "*.png")],
        title="Save Decrypted Image"
    )
    
    if not decrypted_image_path:
        return
    
    with open(decrypted_image_path, "wb") as dec_file:
        dec_file.write(original_data)
    
    messagebox.showinfo("Success", f"Image decrypted successfully!\nSaved as: {decrypted_image_path}")
    
    # Open the decrypted image automatically
    Image.open(decrypted_image_path).show()

# UI Setup
root = tk.Tk()
root.title("Secure Image Encryption")
root.geometry("620x520")
root.config(bg="#34495E")

style = ttk.Style()
style.configure("TButton", font=("Verdana", 12), padding=8, width=22, relief="raised")

header_label = tk.Label(root, text="Image Encryption Tool", font=("Verdana", 18, "bold"), bg="#34495E", fg="white")
header_label.pack(pady=15)

password_label = tk.Label(root, text="Enter Password:", font=("Verdana", 12), bg="#34495E", fg="white")
password_label.pack(pady=8)

password_entry = tk.Entry(root, font=("Verdana", 12), show="*", width=40, relief="solid", bd=2)
password_entry.pack(pady=8)

button_frame = tk.Frame(root, bg="#34495E")
button_frame.pack(pady=20)

encrypt_button = ttk.Button(button_frame, text="Encrypt Image", command=lambda: encrypt_image_ui())
encrypt_button.grid(row=0, column=0, padx=20, pady=10)

decrypt_button = ttk.Button(button_frame, text="Decrypt Image", command=lambda: decrypt_image_ui())
decrypt_button.grid(row=0, column=1, padx=20, pady=10)

def encrypt_image_ui():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password cannot be empty.")
        return
    image_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if not image_path:
        return
    encrypt_image(image_path, password)

def decrypt_image_ui():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password cannot be empty.")
        return
    encrypted_image_path = filedialog.askopenfilename(title="Select an Encrypted Image", filetypes=[("Encrypted Files", "*.bin")])
    if not encrypted_image_path:
        return
    decrypt_image(encrypted_image_path, password)

footer_label = tk.Label(root, text="© 2025 Secure Image Encryption", font=("Verdana", 10), bg="#34495E", fg="#BDC3C7")
footer_label.pack(pady=10)

root.mainloop()
