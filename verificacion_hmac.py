import hmac
import hashlib


def generate_hmac(message: bytes, key: bytes) -> bytes:

    # Validaciones de tipo
    if not isinstance(message, bytes):
        raise ValueError("El mensaje debe ser de tipo bytes.")

    if not isinstance(key, bytes):
        raise ValueError("La clave debe ser de tipo bytes.")

    # Generar y retornar el HMAC
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac(message: bytes, hmac_to_verify: bytes, key: bytes) -> bool:
    """
    Verifica si el HMAC proporcionado es válido para el mensaje dado.

    Args:
        message (bytes): El mensaje que se desea verificar.
        hmac_to_verify (bytes): El HMAC que se quiere comprobar.
        key (bytes): La clave secreta utilizada para calcular el HMAC.

    Returns:
        bool: True si el HMAC coincide; False en caso contrario.

    Raises:
        ValueError: Si el mensaje o la clave no son de tipo bytes.
    """

    # Validaciones de tipo
    if not isinstance(message, bytes):
        raise ValueError("El mensaje debe ser de tipo bytes.")

    if not isinstance(hmac_to_verify, bytes):
        raise ValueError("El HMAC a verificar debe ser de tipo bytes.")

    if not isinstance(key, bytes):
        raise ValueError("La clave debe ser de tipo bytes.")

    # Calcular y comparar el HMAC
    calculated_hmac = generate_hmac(message, key)

    return hmac.compare_digest(calculated_hmac, hmac_to_verify)
