
from Crypto.Cipher import AES
from base64 import b64decode

# 去除补位
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def decrypt(data, key, iv):
    data = b64decode(data)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(data)
    return unpad(data).decode('utf-8')