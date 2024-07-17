import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from PIL import ImageTk


# Steganography functions
def encode_message_in_image(image_path, message, output_image_path):
    image = Image.open(image_path)
    binary_message = "".join([format(ord(char), "08b") for char in message])
    binary_message += "1111111111111110"  # EOF marker
    data_index = 0
    image_data = image.getdata()

    new_image_data = []
    for item in image_data:
        if data_index < len(binary_message):
            new_pixel = tuple(
                [
                    (
                        int(format(value, "08b")[:-1] + binary_message[data_index], 2)
                        if i < 3
                        else value
                    )
                    for i, value in enumerate(item)
                ]
            )
            new_image_data.append(new_pixel)
            data_index += 1
        else:
            new_image_data.append(item)
    image.putdata(new_image_data)
    image.save(output_image_path)


def decode_message_from_image(image_path):
    image = Image.open(image_path)
    binary_message = ""
    image_data = image.getdata()

    for item in image_data:
        for value in item[:3]:
            binary_message += format(value, "08b")[-1]

    binary_message = [
        binary_message[i : i + 8] for i in range(0, len(binary_message), 8)
    ]
    message = ""
    for byte in binary_message:
        if byte == "11111110":
            break
        message += chr(int(byte, 2))
    return message


# Encryption/Decryption functions
def encrypt_message(message, key):
    return "".join(chr(ord(char) + key) for char in message)


def decrypt_message(encrypted_message, key):
    return "".join(chr(ord(char) - key) for char in encrypted_message)


# GUI application
class StegEncryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography and Encryption/Decryption Application")
        self.main_menu()

    def main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(
            self.root,
            text="Steganography and Encryption/Decryption Application",
            font=("Helvetica", 16),
        ).pack(pady=20)
        tk.Button(
            self.root, text="Steganography", command=self.steganography_menu
        ).pack(pady=10)
        tk.Button(
            self.root, text="Encryption/Decryption", command=self.encryption_menu
        ).pack(pady=10)
        tk.Button(self.root, text="Exit", command=self.root.quit).pack(pady=10)

    def steganography_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Steganography", font=("Helvetica", 16)).pack(pady=20)
        tk.Button(
            self.root, text="Encode Message in Image", command=self.encode_message
        ).pack(pady=10)
        tk.Button(
            self.root, text="Decode Message from Image", command=self.decode_message
        ).pack(pady=10)
        tk.Button(self.root, text="Back to Main Menu", command=self.main_menu).pack(
            pady=10
        )

    def encryption_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Encryption/Decryption", font=("Helvetica", 16)).pack(
            pady=20
        )
        tk.Button(
            self.root, text="Encrypt Message", command=self.encrypt_message_menu
        ).pack(pady=10)
        tk.Button(
            self.root, text="Decrypt Message", command=self.decrypt_message_menu
        ).pack(pady=10)
        tk.Button(self.root, text="Back to Main Menu", command=self.main_menu).pack(
            pady=10
        )

    def encode_message(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(
            self.root, text="Encode Message in Image", font=("Helvetica", 16)
        ).pack(pady=20)

        tk.Label(self.root, text="Select Image File:").pack(pady=5)
        self.image_path_entry = tk.Entry(self.root, width=50)
        self.image_path_entry.pack(pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_image).pack(pady=5)

        tk.Label(self.root, text="Enter Message:").pack(pady=5)
        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack(pady=5)

        tk.Label(self.root, text="Output Image File Name:").pack(pady=5)
        self.output_image_entry = tk.Entry(self.root, width=50)
        self.output_image_entry.pack(pady=5)

        tk.Button(self.root, text="Encode", command=self.encode_message_to_image).pack(
            pady=20
        )
        tk.Button(self.root, text="Back", command=self.steganography_menu).pack(pady=10)

    def decode_message(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(
            self.root, text="Decode Message from Image", font=("Helvetica", 16)
        ).pack(pady=20)

        tk.Label(self.root, text="Select Encoded Image File:").pack(pady=5)
        self.encoded_image_path_entry = tk.Entry(self.root, width=50)
        self.encoded_image_path_entry.pack(pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_encoded_image).pack(
            pady=5
        )

        tk.Button(
            self.root, text="Decode", command=self.decode_message_from_image
        ).pack(pady=20)
        tk.Button(self.root, text="Back", command=self.steganography_menu).pack(pady=10)

    def encrypt_message_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Encrypt Message", font=("Helvetica", 16)).pack(
            pady=20
        )

        tk.Label(self.root, text="Enter Message:").pack(pady=5)
        self.encrypt_message_entry = tk.Entry(self.root, width=50)
        self.encrypt_message_entry.pack(pady=5)

        tk.Label(self.root, text="Enter Key (integer):").pack(pady=5)
        self.encrypt_key_entry = tk.Entry(self.root, width=50)
        self.encrypt_key_entry.pack(pady=5)

        tk.Button(self.root, text="Encrypt", command=self.encrypt_message_action).pack(
            pady=20
        )
        tk.Button(self.root, text="Back", command=self.encryption_menu).pack(pady=10)

    def decrypt_message_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Decrypt Message", font=("Helvetica", 16)).pack(
            pady=20
        )

        tk.Label(self.root, text="Enter Encrypted Message:").pack(pady=5)
        self.decrypt_message_entry = tk.Entry(self.root, width=50)
        self.decrypt_message_entry.pack(pady=5)

        tk.Label(self.root, text="Enter Key (integer):").pack(pady=5)
        self.decrypt_key_entry = tk.Entry(self.root, width=50)
        self.decrypt_key_entry.pack(pady=5)

        tk.Button(self.root, text="Decrypt", command=self.decrypt_message_action).pack(
            pady=20
        )
        tk.Button(self.root, text="Back", command=self.encryption_menu).pack(pady=10)

    def browse_image(self):
        self.image_path_entry.delete(0, tk.END)
        file_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg")]
        )
        self.image_path_entry.insert(0, file_path)

    def browse_encoded_image(self):
        self.encoded_image_path_entry.delete(0, tk.END)
        file_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg")]
        )
        self.encoded_image_path_entry.insert(0, file_path)

    def encode_message_to_image(self):
        image_path = self.image_path_entry.get()
        message = self.message_entry.get()
        output_image_path = self.output_image_entry.get()
        if not image_path or not message or not output_image_path:
            messagebox.showerror("Error", "All fields are required!")
            return
        encode_message_in_image(image_path, message, output_image_path)
        messagebox.showinfo("Success", "Message encoded in image successfully!")

    def decode_message_from_image(self):
        encoded_image_path = self.encoded_image_path_entry.get()
        if not encoded_image_path:
            messagebox.showerror("Error", "Image file is required!")
            return
        message = decode_message_from_image(encoded_image_path)
        messagebox.showinfo("Decoded Message", f"Decoded Message: {message}")

    def encrypt_message_action(self):
        message = self.encrypt_message_entry.get()
        try:
            key = int(self.encrypt_key_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Key must be an integer!")
            return
        if not message:
            messagebox.showerror("Error", "Message field is required!")
            return
        encrypted_message = encrypt_message(message, key)
        messagebox.showinfo(
            "Encrypted Message", f"Encrypted Message: {encrypted_message}"
        )

    def decrypt_message_action(self):
        encrypted_message = self.decrypt_message_entry.get()
        try:
            key = int(self.decrypt_key_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Key must be an integer!")
            return
        if not encrypted_message:
            messagebox.showerror("Error", "Encrypted Message field is required!")
            return
        message = decrypt_message(encrypted_message, key)
        messagebox.showinfo("Decrypted Message", f"Decrypted Message: {message}")


if __name__ == "__main__":
    root = tk.Tk()
    app = StegEncryptApp(root)
    root.mainloop()
