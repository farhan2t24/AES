import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Fixed key and IV for AES (in a real app, use secure key management)
key = b'mySecretKey12345'  # 16 bytes
iv = b'mySecretIV123456'  # 16 bytes

def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), AES.block_size)
        return decrypted.decode()
    except Exception as e:
        raise ValueError("Invalid encrypted message")

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption App")
        self.root.geometry("600x400")

        # Sender Side
        sender_frame = tk.Frame(root)
        sender_frame.pack(side=tk.LEFT, padx=20, pady=20)

        tk.Label(sender_frame, text="Sender Side", font=("Arial", 14)).pack()

        self.sender_input = tk.Text(sender_frame, height=5, width=30)
        self.sender_input.pack()
        self.sender_input.bind('<Return>', self.on_enter_press)

        tk.Button(sender_frame, text="ENCRYPT", command=self.encrypt).pack(pady=10)

        self.encrypted_output = tk.Label(sender_frame, text="", wraplength=250, bg="lightgray", height=5)
        self.encrypted_output.pack()

        # Receiver Side
        receiver_frame = tk.Frame(root)
        receiver_frame.pack(side=tk.RIGHT, padx=20, pady=20)

        tk.Label(receiver_frame, text="Receiver Side", font=("Arial", 14)).pack()

        self.receiver_input = tk.Text(receiver_frame, height=5, width=30)
        self.receiver_input.pack()

        tk.Button(receiver_frame, text="DECRYPT", command=self.receiver_decrypt).pack(pady=10)

        self.receiver_encrypted_output = tk.Label(receiver_frame, text="", wraplength=250, bg="lightgray", height=5)
        self.receiver_encrypted_output.pack()

    def encrypt(self):
        message = self.sender_input.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message to encrypt.")
            return
        encrypted = encrypt_message(message)
        self.encrypted_output.config(text=f"Encrypted: {encrypted}")

    def receiver_decrypt(self):
        encrypted_message = self.receiver_input.get("1.0", tk.END).strip()
        if not encrypted_message:
            messagebox.showerror("Error", "Please enter an encrypted message to decrypt.")
            return
        try:
            decrypted = decrypt_message(encrypted_message)
            self.receiver_encrypted_output.config(text=f"Decrypted: {decrypted}")
        except ValueError:
            messagebox.showerror("Error", "Invalid encrypted message.")

    def on_enter_press(self, event):
        self.encrypt()
        message = self.sender_input.get("1.0", tk.END).strip()
        if message:
            self.receiver_input.delete("1.0", tk.END)
            self.receiver_input.insert("1.0", message)
        return 'break'  # Prevent default newline

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
