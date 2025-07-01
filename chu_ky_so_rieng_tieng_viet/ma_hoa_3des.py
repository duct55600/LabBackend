from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def tao_khoa_3des():
    while True:
        khoa = get_random_bytes(24)
        if DES3.adjust_key_parity(khoa):
            return khoa

def tao_iv():
    return get_random_bytes(8)

def ma_hoa_3des(du_lieu: bytes, khoa: bytes, iv: bytes):
    ma_hoa = DES3.new(khoa, DES3.MODE_CBC, iv)
    return ma_hoa.encrypt(pad(du_lieu, DES3.block_size))

def giai_ma_3des(du_lieu_ma_hoa: bytes, khoa: bytes, iv: bytes):
    giai_ma = DES3.new(khoa, DES3.MODE_CBC, iv)
    return unpad(giai_ma.decrypt(du_lieu_ma_hoa), DES3.block_size)
