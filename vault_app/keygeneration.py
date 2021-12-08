
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as hash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def keygenUsingPassword(password):
    salt = b'\x0b\xfd\xb8&\xf1s\x8a\xaa\xbf2\xff\xa3\xc8\xaa\xa9t'
    kdf = PBKDF2HMAC(
        algorithm=hash.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key
