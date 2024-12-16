from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64


def generate_key() -> bytes:
    """Genera una clave AES de 256 bits (32 bytes)."""
    return os.urandom(32)  # Clave aleatoria de 256 bits.


def encrypt_message(key: bytes, plaintext: str) -> str:
    """Cifra un mensaje de texto utilizando AES en modo CBC."""
    iv = os.urandom(16)  # Generar un IV aleatorio.
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    # Retornar IV + ciphertext en Base64
    return base64.b64encode(iv + ciphertext).decode('utf-8')


def decrypt_message(key: bytes, encrypted_message: str) -> str:
    """Descifra un mensaje cifrado utilizando AES en modo CBC."""

    # Decodificar el mensaje cifrado en Base64
    data = base64.b64decode(encrypted_message)

    iv = data[:16]  # Extraer el IV.
    ciphertext = data[16:]  # Extraer el ciphertext.

    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Desencriptar y quitar el padding
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode('utf-8')
