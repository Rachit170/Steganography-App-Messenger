# Steganography-App-Messenger

A modern Python GUI tool for hiding and revealing secret messages in images using steganography and optional encryption.

## Features

- **Hide Messages in Images:** Embed secret text into PNG, BMP, or TIFF images using LSB steganography.
- **Reveal Hidden Messages:** Extract and read hidden messages from images.
- **Optional Encryption:** Secure your messages with password-based AES encryption (Fernet).
- **Modern UI/UX:** Built with [ttkbootstrap](https://ttkbootstrap.readthedocs.io/en/latest/) for a clean, user-friendly interface.
- **Drag-and-Drop & Preview:** Drag images into the app and preview them instantly.
- **Robust Error Handling:** Friendly messages for missing images, wrong passwords, or capacity issues.

## Screenshots


## Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/yourusername/secret-image-messenger.git
    cd secret-image-messenger
    ```

2. **Install dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

    *If you use drag-and-drop, make sure `tkinterdnd2` is installed and `tkdnd` is available in your Python's tcl directory.*

## Usage

1. **Run the app:**
    ```sh
    python steganography_app.py
    ```

2. **Hide a message:**
    - Go to the "Hide Message" tab.
    - Select a cover image (PNG/BMP/TIFF).
    - Type your secret message.
    - (Optional) Check "Encrypt Message" and enter a password.
    - Click "Hide Message in Image" and save the new image.

3. **Reveal a message:**
    - Go to the "Reveal Message" tab.
    - Select an image with a hidden message.
    - (If encrypted) Check "Decrypt Message" and enter the password.
    - Click "Reveal Hidden Message" to see the secret.

## Technologies Used

- Python 3.8+
- [ttkbootstrap](https://ttkbootstrap.readthedocs.io/en/latest/)
- [Pillow (PIL)](https://python-pillow.org/)
- [cryptography](https://cryptography.io/)
- [tkinterdnd2](https://github.com/pmgagne/tkinterdnd2) (for drag-and-drop)

## License

MIT License

---

**Happy hiding!**
