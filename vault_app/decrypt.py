import os
from cryptography.fernet import Fernet
from vault_app.keygeneration import *


def decrypt_file(filepath, passkey):
    try:
        f = open(filepath, 'rb')
        data = f.read()
        password = passkey
        fernetHandler = Fernet(keygenUsingPassword(password.strip()))
        try:
            decryptedData = fernetHandler.decrypt(data)
            f.close()
            os.remove(filepath)
            f = open(filepath, "wb")
            f.write(decryptedData)
            return 1
        except:
            return -1
    except:
        return 0
