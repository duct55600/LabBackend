from Crypto.PublicKey import RSA

def tao_khoa(ten_file):
    khoa = RSA.generate(2048)
    with open(f"{ten_file}.pem", "wb") as f:
        f.write(khoa.export_key())
    with open(f"{ten_file}_cong_khai.pem", "wb") as f:
        f.write(khoa.publickey().export_key())

tao_khoa("khoa_gui")
tao_khoa("khoa_nhan")
print("Đã tạo xong khóa!")
