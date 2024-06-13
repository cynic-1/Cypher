import rsa
import base64

# 生成RSA公私钥对
(pubkey, privkey) = rsa.newkeys(2048)

# 公钥和私钥可以序列化并传输
public_key = pubkey.save_pkcs1()
private_key = privkey.save_pkcs1()

# 加密和解密函数
def encrypt(message, public_key):
    message = message.encode('utf-8')
    pubkey = rsa.PublicKey.load_pkcs1(public_key)
    encrypted = rsa.encrypt(message, pubkey)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(encrypted, private_key):
    encrypted = base64.b64decode(encrypted)
    privkey = rsa.PrivateKey.load_pkcs1(private_key)
    decrypted = rsa.decrypt(encrypted, privkey)
    return decrypted.decode('utf-8')

# 使用示例
message = "Hello, World!"
encrypted_message = encrypt(message, public_key)
decrypted_message = decrypt(encrypted_message, private_key)

print(f"Original Message: {message}")
print(f"Encrypted Message: {encrypted_message}")
print(f"Decrypted Message: {decrypted_message}")