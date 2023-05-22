import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def generate_rsa_key_pair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize the keys to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem


def find_private_exponent(e, phi_n):
    # Find the private exponent d using extended Euclidean algorithm
    d = 0
    x1, x2, y1, y2 = 0, 1, 1, 0

    while phi_n != 0:
        quotient = e // phi_n
        e, phi_n = phi_n, e % phi_n
        x1, x2 = x2 - quotient * x1, x1
        y1, y2 = y2 - quotient * y1, y1

    if x2 < 0:
        d = x2 + phi_n
    else:
        d = x2

    return d


def sign_message(message, private_key_pem):
    # Load private key from PEM format
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Sign the message with RSA private key
    signature = private_key.sign(
        message,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(message, signature, public_key_pem):
    # Load public key from PEM format
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    # Verify the signature with RSA public key
    try:
        public_key.verify(
            signature,
            message,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def rsa_encrypt(message, public_key_pem):
    # Load public key from PEM format
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    # Encrypt the message with RSA public key
    ciphertext = public_key.encrypt(
        message,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


def rsa_decrypt(ciphertext, private_key_pem):
    # Load private key from PEM format
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Decrypt the ciphertext with RSA private key
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext


def encrypt_with_3des(key, message):
    # Generate random IV
    iv = os.urandom(8)

    # Pad the message
    padder = padding.PKCS7(64).padder()
    padded_message = padder.update(message) + padder.finalize()

    # Create the 3DES cipher
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())

    # Encrypt the padded message with 3DES
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Return the IV and ciphertext
    return iv + ciphertext


def decrypt_with_3des(key, ciphertext):
    # Extract the IV and ciphertext
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]

    # Create the 3DES cipher
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the ciphertext with 3DES
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the message
    unpadder = padding.PKCS7(64).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message



