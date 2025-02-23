🖼️ Image Encryption & Decryption with Steganography 🔐

Welcome to the Image Encryption & Decryption with Steganography project! 🎉 This tool enables secure encryption and decryption of images using AES encryption, along with the ability to conceal sensitive data within images using Least Significant Bit (LSB) steganography. 🔒

With this project, you can protect confidential data by embedding it into images in a way that is undetectable to the human eye. Whether you want to secure your images or secretly share messages, this tool provides the perfect solution! 🚀

🌟 Features:

🔐 AES Encryption: Strong encryption to protect image data with a password.

💻 LSB Steganography: Hide encrypted data inside an image while keeping it visually unchanged.

📸 Automatic Image Viewer: The decrypted image opens immediately after decryption.

🛠️ User-Friendly Interface: Designed with Tkinter, providing an intuitive GUI for easy navigation.

🔍 Secure Communication: Ensures that encrypted and hidden data remains undetectable.

⚡ How to Use:

1️⃣ Encrypt an Image:

Click "Encrypt Image".

Select an image from your computer.

Enter a password for encryption.

Save the encrypted image with the hidden data.

2️⃣ Decrypt an Image:

Click "Decrypt Image".

Select the encrypted image.

Enter the correct password.

The decrypted image is displayed automatically! 😎

🔧 Requirements:

Python 3.x 🐍

Pillow (PIL) 🖼️ for image processing

Cryptography Library 🔒 for AES encryption

Stegano Library 🕵️‍♂️ for hiding and revealing messages

Install Required Libraries:

pip install pillow cryptography stegano

🌍 How It Works:

1️⃣ AES Encryption:

AES (Advanced Encryption Standard) is used to encrypt image data securely. This ensures that only users with the correct password can access the original content. 🔐

2️⃣ LSB Steganography:

After encryption, the encrypted data is hidden within an image using Least Significant Bit (LSB) steganography. This technique modifies the least significant bits of pixel values to store secret information without affecting the image’s appearance. 🤫

3️⃣ Decryption:

To retrieve the hidden message, the correct password is required. The encrypted data is extracted from the image and decrypted back into its original form. 🧩

🧑‍💻 Example:

Encryption Example:

You have an image (e.g., secure.jpg). 🏖️

You enter a password (my_secure_pass). 🔑

The image is encrypted and saved as secure_encrypted.png (with hidden data inside).

The encrypted image can now be shared securely with authorized recipients.

Decryption Example:

The recipient receives secure_encrypted.png.

They enter the password (my_secure_pass).

The image is decrypted and displayed automatically! 🌈

💡 Tips:

🔑 Use a Strong Password for maximum security.

🌍 Supported Formats: PNG, JPEG, and JPG images can be used for encryption.

🕵️‍♂️ Hide Text Inside Images: This tool can also be used to secretly store important text files inside images. 📄🎨

⚠️ Warnings:

🚨 Lost passwords cannot be recovered! Store them securely.

📉 If an image does not contain hidden data, decryption will fail.

🛑 Ensure that the encrypted image is saved correctly before closing the application.

📸 Screenshots:

📌 Encrypting an Image:
Select a file, enter a password, and encrypt it securely.

📌 Decrypting an Image:
Retrieve and view the hidden data from the encrypted image.

📜 License:

This project is licensed under the MIT License. See the LICENSE file for details. 📄

🙋‍♂️ Need Help?

If you have any questions or need assistance, feel free to contact me. I'm happy to help! 😃

📩 Email: podamounitha.4829@gmail.com


🎉 Enjoy using this tool for secure image encryption and steganography! 🚀🔐


