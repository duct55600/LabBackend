# nguoi_nhan.py
import json
from ma_hoa_rsa import tai_khoa_bi_mat, tai_khoa_cong_khai, giai_ma_bang_rsa_khoa_bi_mat, kiem_tra_chu_ky # Import chính xác
from ma_hoa_3des import giai_ma_3des
from bam_sha512 import bam_hoa # Giữ lại import này

from base64 import b64decode

# Tải khóa
khoa_bi_mat_nhan = tai_khoa_bi_mat('khoa_nhan.pem')
khoa_cong_khai_gui = tai_khoa_cong_khai('khoa_gui_cong_khai.pem')

# Đọc JSON
with open("goi_tin.json", "r") as f:
    du_lieu = json.load(f)

# Giải mã khóa phiên
khoa_phien = giai_ma_bang_rsa_khoa_bi_mat(b64decode(du_lieu["khoa_phien_ma_hoa"]), khoa_bi_mat_nhan) # Gọi đúng hàm

# Xác minh metadata
metadata = du_lieu["metadata"].encode()
chu_ky_metadata = b64decode(du_lieu["chu_ky_metadata"])
if not kiem_tra_chu_ky(metadata, chu_ky_metadata, khoa_cong_khai_gui): # Gọi đúng hàm
    print("[Người Nhận] Metadata không hợp lệ! Gửi NACK.")
    exit()

# Giải mã các phần
cac_phan = []
for i, phan in enumerate(du_lieu["cac_phan"]):
    iv = b64decode(phan["iv"])
    du_lieu_ma_hoa = b64decode(phan["ma_hoa"])
    bam = bytes.fromhex(phan["bam"])
    chu_ky = b64decode(phan["chu_ky"])

    # Cần hash lại dữ liệu để so sánh với bam đã nhận được
    if bam_hoa(iv + du_lieu_ma_hoa) != bam: # bam_hoa trả về bytes, so sánh trực tiếp
        print(f"[Người Nhận] Phần {i+1} sai mã băm. Gửi NACK.")
        exit()

    # Lưu ý: Hàm kiem_tra_chu_ky yêu cầu đối số đầu tiên là dữ liệu gốc ĐÃ BĂM.
    # bam ở đây đã là digest, nên truyền trực tiếp.
    if not kiem_tra_chu_ky(bam, chu_ky, khoa_cong_khai_gui): # Gọi đúng hàm và truyền đúng đối số
        print(f"[Người Nhận] Phần {i+1} sai chữ ký. Gửi NACK.")
        exit()

    giai_ma = giai_ma_3des(du_lieu_ma_hoa, khoa_phien, iv)
    cac_phan.append(giai_ma)

with open("hop_dong_nhan_duoc.txt", "wb") as f:
    f.write(b"".join(cac_phan))

print("[Người Nhận] Hợp lệ. Đã tạo hop_dong_nhan_duoc.txt. Gửi ACK.")