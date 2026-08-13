# HỆ THỐNG MÃ HÓA & LƯU TRỮ ẢNH AN TOÀN DUNG LƯỢNG LỚN (AES-256-GCM HYBRID)

> **Dự án Luận văn Thạc sĩ CNTT / An toàn Thông tin**
> Nghiên cứu & Triển khai Hệ thống Mã hóa Ảnh Dung lượng lớn áp dụng Mật mã Lai 2 Lớp (AES-256-GCM + PBKDF2 KDF) tích hợp Khóa Bảo mật Phần cứng (USB Hardware-Binding / PKCS#11) và Xử lý Luồng (Streaming Chunking).

---

## 🌟 TÍNH NĂNG NỔI BẬT

1. **Thuật toán Cốt lõi (Core Security):**
   - Sử dụng **AES-256-GCM** (Galois/Counter Mode) thuộc chuẩn **AEAD** (Authenticated Encryption with Associated Data).
   - Vừa bảo mật dữ liệu (Confidentiality) vừa kiểm tra tính toàn vẹn (Integrity) nhờ **16-byte Auth Tag** tự động.

2. **Quản lý Khóa Lai 2 Lớp (Hybrid Key Management & Hardware-Binding):**
   - **Data Encryption Key (DEK):** Sinh ngẫu nhiên 256-bit độc lập cho từng tệp ảnh.
   - **Key Encryption Key (KEK / Master Key):** Sinh ngẫu nhiên từ sự kết hợp giữa **[Bí mật Phần cứng USB]** + **[Mã PIN Người dùng]** thông qua hàm KDF `PBKDF2-HMAC-SHA256` ($100.000+$ iterations).

3. **Mã hóa Luồng Dữ liệu Dung lượng lớn (Streaming / Chunked Processing):**
   - Chia nhỏ tệp tin thành các khối (Chunk 4MB), đọc/ghi nối tiếp.
   - **Dung lượng RAM tiêu thụ duy trì ở mức cố định $<30\text{ MB}$** ngay cả khi xử lý các tệp ảnh siêu lớn ($33\text{GB}+$).

4. **Mô hình Bảo mật Vòng đời Dữ liệu (Model A - In-place Encryption & Auto-Cleanup):**
   - **Khi Mã hóa:** Tạo tệp `.enc` thành công $\rightarrow$ **Tự động xóa vĩnh viễn tệp ảnh gốc**.
   - **Khi Giải mã:** Phôi phục tệp ảnh gốc thành công $\rightarrow$ **Tự động dọn dẹp tệp `.enc` rác**.

5. **Xử lý Song song (Batch Encryption Multiprocessing):**
   - Hỗ trợ mã hóa hàng loạt hàng chục nghìn ảnh ($34.980+$ ảnh) tự động sử dụng đa nhân CPU với cơ chế lưu trạng thái Checkpoint chống ngắt điện đột ngột.

---

## 🏗️ CẤU TRÚC DỰ ÁN

```text
MaHoaAnH_Project/
├── main.py                 # Core Crypto Engine & Giao diện Desktop GUI (CustomTkinter)
├── batch_encrypt.py        # Script mã hóa hàng loạt song song (Multiprocessing Batch Mode)
├── generate_charts.py      # Bộ công cụ xuất biểu đồ hiệu năng & trực quan hóa báo cáo
├── demo_secure_key_location/# Thư mục mô phỏng khóa phần cứng (Giai đoạn 1A)
├── requirements.txt        # Danh sách thư viện phụ thuộc
├── README.md               # Tài liệu hướng dẫn dự án
└── report_charts/          # Các biểu đồ & hình ảnh thực nghiệm xuất cho luận văn
    ├── chart_ram_benchmark.png
    ├── chart_speed_benchmark.png
    └── visual_image_comparison.png
```

---

## 🛠️ HƯỚNG DẪN CÀI ĐẶT & CHẠY ỨNG DỤNG

### 1. Cài đặt các thư viện phụ thuộc
```bash
pip install cryptography customtkinter Pillow psutil pywin32 matplotlib
```

### 2. Khởi chạy Giao diện Desktop (GUI App)
```bash
python main.py
```
- Đèn báo trạng thái phần cứng tự động kiểm tra USB (`E:\device_secret.key`).
- Chọn tệp lẻ hoặc chọn nguyên thư mục ảnh gốc/thư mục `.enc`.
- Nhập PIN (ví dụ: `88886666`) và bấm **MÃ HÓA** hoặc **GIẢI MÃ**.

### 3. Khởi chạy Mã hóa Hàng loạt (Batch Mode cho Dataset lớn)
```bash
python batch_encrypt.py 88886666
```

### 4. Tạo lại các Biểu đồ Báo cáo Thực nghiệm (300 DPI)
```bash
python generate_charts.py
```

---

## 📊 CẤU TRÚC TỆP MÃ HÓA (.ENC BINARY FORMAT)

| Offset | Trường dữ liệu | Kích thước | Mô tả |
| :--- | :--- | :--- | :--- |
| `0x00 - 0x07` | Magic Header | 8 Bytes | Chuỗi nhận dạng cố định `SECIMG01` |
| `0x08 - 0x0B` | Header Length | 4 Bytes | Độ dài Metadata JSON (Big-Endian uint32) |
| `0x0C - N` | Metadata JSON | Khả biến | Chứa `salt`, `dek_nonce`, `encrypted_dek`, `chunk_size` |
| `N+1 - End` | Payload Stream | Khả biến | Chuỗi khối: `[CHUNK_LEN (4B)] + [NONCE (12B)] + [CYPHERTEXT + TAG (16B)]` |

---

## 📄 GIẤY PHÉP & BẢO QUYỀN
Dự án được bảo vệ bản quyền nghiên cứu thuộc Luận văn Thạc sĩ An toàn Thông tin / Công nghệ Thông tin.