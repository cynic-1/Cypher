import json

from cryptography.hazmat.primitives.asymmetric import rsa

import socket
import base64
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify

# 加密和解密函数
def rsa_encrypt(message, public_key):
    message = message.encode('utf-8')
    pubkey = rsa.PublicKey.load_pkcs1(public_key)
    encrypted = rsa.encrypt(message, pubkey)
    return base64.b64encode(encrypted).decode('utf-8')


def rsa_decrypt(encrypted, private_key):
    encrypted = base64.b64decode(encrypted)
    privkey = rsa.PrivateKey.load_pkcs1(private_key)
    decrypted = rsa.decrypt(encrypted, privkey)
    return decrypted.decode('utf-8')


def generate_aes_key():
    """生成指定长度的AES密钥并返回其十六进制字符串表示"""
    key = get_random_bytes(32)
    return hexlify(key).decode('ascii')

def aes_encrypt(data, key):
    """使用AES算法加密数据"""
    key_bytes = bytes.fromhex(key)  # 将十六进制字符串转换回字节
    iv = get_random_bytes(AES.block_size)  # 初始化向量
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))  # 对数据进行填充
    return iv + ct_bytes

def aes_decrypt(data, key):
    """使用AES算法解密数据"""
    key_bytes = bytes.fromhex(key)  # 将十六进制字符串转换回字节
    iv = data[:AES.block_size]
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv)
    pt = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)  # 移除填充
    return pt

def read_public_key_from_file(filename):
    # 打开公钥文件并读取内容
    with open(filename, "rb") as public_key_file:
        public_key = public_key_file.read()
    return public_key

# 客户端
def client():
    # 创建一个 TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 连接服务端
    server_address = ('localhost', 12345)
    print('Connecting to {} port {}'.format(*server_address))
    client_socket.connect(server_address)
    (pubkey, privkey) = rsa.newkeys(2048)
    private_key_client = privkey.save_pkcs1()
    public_key_client = pubkey.save_pkcs1()
    try:
        # 发送数据
        public_key = read_public_key_from_file("public_key.pem")
        message_dict = {
            'mode': "1",
            'public_key_client': rsa_encrypt(public_key_client.decode('utf-8'), public_key)
        }
        message_json = json.dumps(message_dict)
        print('Sending:', message_json)
        client_socket.sendall(message_json.encode())
        data = client_socket.recv(4096)
        if data:
            data_dict = eval(data)
            if data_dict['mode'] == '1':
                con_key = rsa_decrypt(data_dict['con_key'], private_key_client)
                print('Receive con_key:' + data_dict['con_key'])
                message_dict2 = {
                    'mode': "2",
                    'message': hexlify(aes_encrypt("Hello!".encode(), con_key)).decode('ascii')
                }
                message_json2 = json.dumps(message_dict2)
                print('Sending:', message_json2)
                client_socket.sendall(message_json2.encode())
    finally:
        # 关闭连接
        print('Closing socket')
        client_socket.close()


if __name__ == "__main__":
    client()
