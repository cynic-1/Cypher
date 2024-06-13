import json


from cryptography.hazmat.primitives.asymmetric import rsa

import socket
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify
import base64
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



# 服务器生成密钥对
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


def save_keys_to_files(private_key, public_key):
    # 将私钥保存到文件
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key)

    # 将公钥保存到文件
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key)

# 服务器端
def server():
    # (pubkey, privkey) = rsa.newkeys(4096)
    # private_key_server = privkey.save_pkcs1()
    # public_key_server = pubkey.save_pkcs1()
    # save_keys_to_files(private_key_server, public_key_server)
    public_key_server = read_public_key_from_file("public_key.pem")
    private_key_server = read_public_key_from_file("private_key.pem")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    con_key = generate_aes_key()  # 服务器生成AES对称密钥作为会话密钥
    server_socket.listen(5)

    while True:
        print('Waiting for a connection...')
        connection, client_address = server_socket.accept()
        try:
            print('Connection from', client_address)
            # 接收数据
            while True:
                data = connection.recv(4096)

                if data:
                    data_dict = eval(data)
                    print('Received:', data_dict)
                    if data_dict['mode'] == '1':
                        public_key_client = rsa_decrypt(data_dict['public_key_client'], private_key_server).encode()
                        data_dict2 = {
                            'mode': '1',
                            'con_key': rsa_encrypt(con_key, public_key_client)
                        }
                        data_json2 = json.dumps(data_dict2)
                        print('Sending data back to the client')
                        connection.sendall(data_json2.encode())
                    if data_dict['mode'] == '2':
                        message = aes_decrypt(bytes.fromhex(data_dict['message']), con_key).decode()
                        print('Receive message:' + message)
                else:
                    print('No more data from', client_address)
                    break
        finally:
            # 关闭连接
            connection.close()


if __name__ == "__main__":
    server()
