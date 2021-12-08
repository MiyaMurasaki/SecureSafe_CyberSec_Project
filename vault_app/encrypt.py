import os
from cryptography.fernet import Fernet
from vault_app.keygeneration import *


def encrypt_file(filepath, passkey):
    try:
        f = open(filepath, 'rb')
        data = f.read()
        password = passkey
        fernetHandler = Fernet(keygenUsingPassword(password.strip()))
        encryptedData = fernetHandler.encrypt(data)
        f.close()
        os.remove(filepath)
        f = open(filepath, "wb")
        f.write(encryptedData)
        return 1
    except:
        return 0
