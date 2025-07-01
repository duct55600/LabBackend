import os
import json
import time
import base64
from ma_hoa_rsa import tai_khoa_bi_mat, tai_khoa_cong_khai, ky_du_lieu, ma_hoa_bang_rsa_khoa_cong_khai
from ma_hoa_3des import tao_khoa_3des, tao_iv, ma_hoa_3des
from bam_sha512 import bam_hoa

print("--- BẮT ĐẦU KỊCH BẢN NGƯỜI GỬI ---")

# --- 0. Kiểm tra sự tồn tại của các file cần thiết ---
ten_file = "contract.txt"
if not os.path.exists(ten_file):
    print(f"[LỖI] Không tìm thấy file '{ten_file}'.")
    print("Vui lòng tạo file 'contract.txt' trong cùng thư mục và chạy lại chương trình.")
    exit()

if not os.path.exists("khoa_gui.pem") or not os.path.exists("khoa_nhan_cong_khai.pem"):
    print("[LỖI] Không tìm thấy file khóa (khoa_gui.pem hoặc khoa_nhan_cong_khai.pem).")
    print("Vui lòng chạy script 'tao_khoa.py' trước.")
    exit()

# --- 1. Tải khóa ---
try:
    khoa_bi_mat_gui = tai_khoa_bi_mat("khoa_gui.pem")
    khoa_cong_khai_nhan = tai_khoa_cong_khai("khoa_nhan_cong_khai.pem")
    print("- Đã tải khóa của Người gửi và khóa công khai của Người nhận thành công.")
except Exception as e:
    print(f"[LỖI] Không thể tải file khóa: {e}")
    exit()

# --- 2. Handshake ---
print("\n--- Giai đoạn Handshake ---")
print("Người gửi: Hello!")
# Trong thực tế, đây sẽ là một cơ chế lắng nghe mạng.
# Ở đây chúng ta mô phỏng bằng cách chờ người dùng xác nhận.
response = input(">>> Người nhận có đồng ý nhận file không? (Nhập 'yes' hoặc 'y' để tiếp tục, bất kỳ phím nào khác để hủy): ").lower()

if response not in ['yes', 'y']:
    print("[THÔNG BÁO] Người nhận đã từ chối. Phiên gửi bị hủy bỏ.")
    exit()

print(">>> Đã nhận tín hiệu 'Ready!' từ Người nhận. Tiếp tục quá trình...")


# --- 3. Tạo khóa phiên & mã hóa bằng RSA (Phong bì số) ---
print("\n--- Giai đoạn Chuẩn bị Dữ liệu ---")
session_key = tao_khoa_3des()
session_key_ma_hoa = ma_hoa_bang_rsa_khoa_cong_khai(session_key, khoa_cong_khai_nhan)
print("- Đã tạo và mã hóa khóa phiên (session key) bằng RSA.")

# --- 4. Tạo metadata và ký ---
timestamp = str(int(time.time()))
kich_thuoc = str(os.path.getsize(ten_file))
metadata = f"{ten_file}|{timestamp}|{kich_thuoc}".encode("utf-8")
chu_ky_metadata = ky_du_lieu(metadata, khoa_bi_mat_gui)
print(f"- Đã tạo và ký metadata cho file '{ten_file}'.")

# --- 5. Đọc nội dung file, chia 3 phần ---
with open(ten_file, "rb") as f:
    noi_dung = f.read()

# Tính toán để chia file thành 3 phần một cách chính xác nhất
part_size = (len(noi_dung) + 2) // 3
cac_phan = [noi_dung[i:i + part_size] for i in range(0, len(noi_dung), part_size)]
print(f"- Đã chia file thành {len(cac_phan)} phần.")

# --- 6. Mã hóa và ký từng phần ---
print("- Bắt đầu mã hóa và ký từng phần...")
cac_phan_ma_hoa = []
for i, phan in enumerate(cac_phan):
    iv = tao_iv()
    du_lieu_ma_hoa = ma_hoa_3des(phan, session_key, iv)
    # Hash của (IV || Ciphertext)
    bam = bam_hoa(iv + du_lieu_ma_hoa)
    # Ký lên hash
    chu_ky = ky_du_lieu(bam, khoa_bi_mat_gui)

    goi_tin_phan = {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ma_hoa": base64.b64encode(du_lieu_ma_hoa).decode("utf-8"),
        "bam": bam.hex(),
        "chu_ky": base64.b64encode(chu_ky).decode("utf-8")
    }
    cac_phan_ma_hoa.append(goi_tin_phan)
    print(f"  + Đã xử lý xong phần {i+1}/{len(cac_phan)}.")

# --- 7. Ghi file goi_tin.json chứa toàn bộ thông tin ---
du_lieu_gui_di = {
    "metadata": metadata.decode("utf-8"),
    "chu_ky_metadata": base64.b64encode(chu_ky_metadata).decode("utf-8"),
    "khoa_phien_ma_hoa": base64.b64encode(session_key_ma_hoa).decode("utf-8"),
    "cac_phan": cac_phan_ma_hoa
}

with open("goi_tin.json", "w") as f:
    json.dump(du_lieu_gui_di, f, indent=4)

print("\n--- HOÀN THÀNH ---")
print("Người gửi đã tạo thành công file 'goi_tin.json'.")
print("File này đã sẵn sàng để gửi cho Người nhận.")
