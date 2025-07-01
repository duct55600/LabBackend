from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import PKCS1_OAEP # Bạn cần import cái này để giải mã

def tai_khoa_bi_mat(duong_dan):
    with open(duong_dan, 'rb') as f:
        return RSA.import_key(f.read())

def tai_khoa_cong_khai(duong_dan):
    with open(duong_dan, 'rb') as f:
        return RSA.import_key(f.read())

def ky_du_lieu(du_lieu, khoa_bi_mat):
    bam = SHA512.new(du_lieu)
    chu_ky = pkcs1_15.new(khoa_bi_mat).sign(bam)
    return chu_ky

def ma_hoa_bang_rsa_khoa_cong_khai(du_lieu, khoa_cong_khai):
    # from Crypto.Cipher import PKCS1_OAEP # Đã import ở đầu file
    cipher_rsa = PKCS1_OAEP.new(khoa_cong_khai)
    return cipher_rsa.encrypt(du_lieu)

# THÊM HÀM NÀY VÀO FILE MA_HOA_RSA.PY
def giai_ma_bang_rsa_khoa_bi_mat(du_lieu_ma_hoa, khoa_bi_mat):
    """
    Giải mã dữ liệu đã mã hóa bằng RSA với khóa bí mật.
    """
    # Đảm bảo bạn đã import Crypto.Cipher.PKCS1_OAEP ở đầu file
    cipher_rsa = PKCS1_OAEP.new(khoa_bi_mat)
    return cipher_rsa.decrypt(du_lieu_ma_hoa)

def kiem_tra_chu_ky(du_lieu, chu_ky, khoa_cong_khai):
    bam = SHA512.new(du_lieu)
    try:
        pkcs1_15.new(khoa_cong_khai).verify(bam, chu_ky)
        return True
    except (ValueError, TypeError):
        return False
giai_ma_rsa = giai_ma_bang_rsa_khoa_bi_mat