from PIL import Image
from cryptography.fernet import Fernet
import base64, hashlib

DELIMITER = "###END_OF_MESSAGE###"

def get_fernet_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode()).decode()

def decrypt_message(message, key):
    return Fernet(key).decrypt(message.encode()).decode()

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary):
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

def embed_message_in_image(image, message, save_path):
    message += DELIMITER
    binary_data = text_to_binary(message)
    width, height = image.size
    max_capacity = width * height * 3
    if len(binary_data) > max_capacity:
        raise ValueError("Message too long for selected image.")

    pixels = list(image.getdata())
    new_pixels = []
    idx = 0

    for pixel in pixels:
        r, g, b = pixel[:3]
        if idx < len(binary_data):
            r = (r & ~1) | int(binary_data[idx])
            idx += 1
        if idx < len(binary_data):
            g = (g & ~1) | int(binary_data[idx])
            idx += 1
        if idx < len(binary_data):
            b = (b & ~1) | int(binary_data[idx])
            idx += 1
        new_pixels.append((r, g, b))

    new_image = Image.new('RGB', image.size)
    new_image.putdata(new_pixels)
    new_image.save(save_path)

def extract_message_from_image(image):
    pixels = list(image.getdata())
    binary_data = ''
    for pixel in pixels:
        for channel in pixel[:3]:
            binary_data += str(channel & 1)

    text = ''
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) == 8:
            char = chr(int(byte, 2))
            text += char
            if text.endswith(DELIMITER):
                return text[:-len(DELIMITER)]
    raise ValueError("No message found.")
