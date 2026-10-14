from Crypto.Cipher import AES  # 导入AES加密模块
from secret import flag       # 从secret模块导入flag（假设为明文）
import random, os             # 导入random和os模块用于随机数生成

# 为消息填充字节，使其长度为16的倍数
def pad(msg):
    return msg + bytes([16 - len(msg) % 16 for _ in range(16 - len(msg) % 16)])

# 对密钥进行随机置换，生成新密钥
def permutation(key):
    tables = [hex(_)[2:] for _ in range(16)]  # 生成0-15的十六进制表（去掉"0x"前缀）
    random.shuffle(tables)                    # 随机打乱表
    newkey = "".join(tables[int(key[_], 16)] for _ in range(len(key)))  # 根据原密钥生成新密钥
    return newkey

# 生成初始密钥key0及其置换密钥key1
def gen():
    key0 = os.urandom(16).hex()  # 随机生成16字节密钥并转为十六进制字符串
    key1 = permutation(key0)     # 对key0进行置换生成key1
    return key0, key1

# 使用key0和key1进行双重AES加密
def encrypt(key0, key1, msg):
    aes0 = AES.new(key0, AES.MODE_CBC, key1)  # 用key0加密，key1作为CBC模式的IV
    aes1 = AES.new(key1, AES.MODE_CBC, key0)  # 用key1解密，key0作为CBC模式的IV
    return aes1.decrypt(aes0.encrypt(msg))    # 先加密后解密生成密文

# 生成密钥对
key0, key1 = gen()
a0, a1 = int(key0, 16), int(key1, 16)  # 将密钥转为整数

gift = a0 & a1  # 计算key0和key1的按位与，作为泄露信息
cipher = encrypt(bytes.fromhex(key0), bytes.fromhex(key1), pad(flag))  # 加密填充后的flag

print(f"gift = {gift}")
print(f"key1 = {key1}")
print(f"cipher = {cipher}")

'''
gift = 64698960125130294692475067384121553664
key1 = 74aeb356c6eb74f364cd316497c0f714
cipher = b'6\xbf\x9b\xb1\x93\x14\x82\x9a\xa4\xc2\xaf\xd0L\xad\xbb5\x0e|>\x8c|\xf0^dl~X\xc7R\xcaZ\xab\x16\xbe r\xf6Pl\xe0\x93\xfc)\x0e\x93\x8e\xd3\xd6'
'''