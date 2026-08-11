# HỆ THỐNG MÃ HÓA & LƯU TRỮ ẢNH AN TOÀN (Image-Encryption-Tool)

Dự án này là hệ thống phần mềm hỗ trợ mã hóa và giải mã hình ảnh/dữ liệu an toàn, được phát triển phục vụ cho Đồ án/Luận văn Thạc sĩ. Hệ thống sử dụng thuật toán mã hóa mạnh mẽ **AES-256-GCM Hybrid** kết hợp với **Khóa Bảo mật Phần cứng (Hardware Key)** để đảm bảo an toàn tối đa cho dữ liệu.

## Tính năng nổi bật
* **Mã hóa AES-256-GCM:** Sử dụng chuẩn mã hóa tiên tiến có xác thực, đảm bảo tính bí mật và toàn vẹn của dữ liệu hình ảnh. Bất cứ sự can thiệp nào vào tệp mã hóa đều sẽ bị phát hiện (Cơ chế GCM Auth Tag).
* **Tích hợp Khóa Phần Cứng (Hardware Security):** Hệ thống yêu cầu kết hợp giữa mã PIN và khóa bí mật lưu trên phần cứng (USB, Thư mục bảo mật mô phỏng hoặc HSM qua PKCS#11) để tạo khóa mã hóa (Key Encryption Key - KEK) thông qua PBKDF2.
* **Xử lý Streaming (Chunking):** Tối ưu hóa RAM cho các tệp ảnh/dữ liệu cực lớn (hỗ trợ đến 33GB+) bằng cách chia nhỏ dữ liệu thành các khối 4MB để xử lý thay vì nạp toàn bộ dữ liệu vào RAM.
* **Giao diện hiện đại (GUI):** Ứng dụng tích hợp giao diện người dùng hiện đại, thân thiện Dark Mode, được xây dựng bằng `customtkinter`.
* **Xử lý Hàng loạt (Batch Processing):** Hỗ trợ mã hóa hàng loạt dataset cực lớn bằng đa luồng/đa tiến trình (Multiprocessing), tích hợp tính năng tự động lưu điểm neo (`checkpoint.json`) để khôi phục tiến trình đang chạy dở dang.
* **Công cụ Báo cáo Trực quan:** Chứa script tự động tạo biểu đồ so sánh hiệu suất tiêu thụ RAM và tốc độ xử lý phục vụ báo cáo khoa học.

## Cấu trúc Dự án
* `main.py`: Chứa ứng dụng GUI chính, bộ công cụ mã hóa `SecureImageCryptoEngine`, và các lớp quản lý giao tiếp thiết bị (Folder, USB, PKCS#11).
* `batch_encrypt.py`: Script CLI mã hóa hàng loạt dành cho dữ liệu lớn. Tối đa hóa công suất CPU bằng `ProcessPoolExecutor`.
* `generate_charts.py`: Script xuất các biểu đồ trực quan (RAM benchmark, Speed benchmark, Hiệu quả bảo mật) cho báo cáo luận văn.
* `demo_secure_key_location/`: Thư mục mô phỏng thiết bị phần cứng để lưu trữ tệp khóa bí mật (`device_secret.key`). Dùng trong trường hợp chưa có USB thật.
* `report_charts/`: Thư mục chứa các biểu đồ kết xuất sau khi chạy script.

## Yêu cầu Hệ thống
* Python 3.8 trở lên
* Cài đặt các thư viện phụ thuộc:
```bash
pip install cryptography customtkinter psutil matplotlib Pillow
```

## Hướng dẫn Sử dụng

### 1. Giao diện Ứng dụng Chính (GUI)
Chạy tệp `main.py` để mở giao diện:
```bash
python main.py
```
* **Nguồn Khóa Phần Cứng:** Có thể chọn nguồn cấp khóa tương ứng từ Dropdown (USB Thật, Thư mục mô phỏng, hoặc PKCS#11).
* **Thao tác:** Chọn một tệp lẻ hoặc cả thư mục cần mã hóa/giải mã, nhập mã PIN và chọn nơi lưu trữ kết quả.

### 2. Mã hóa Hàng loạt (Batch Processing)
Phù hợp để xử lý toàn bộ dataset. Chạy tệp `batch_encrypt.py` qua Command Line:
```bash
python batch_encrypt.py [PIN]
```
*(Lưu ý: Bạn có thể cần vào tệp `batch_encrypt.py` để tinh chỉnh lại đường dẫn cấu hình `RAW_DATA_DIR` và thư mục Output trước khi chạy).*

### 3. Tạo Biểu Đồ Đánh Giá
Chạy script dưới đây để xuất các biểu đồ (benchmark tốc độ và RAM) phục vụ cho tài liệu nghiên cứu:
```bash
python generate_charts.py
```
Các hình ảnh kết xuất sẽ nằm ở thư mục `report_charts/`.

## Cơ chế Bảo mật Cốt lõi
Hệ thống kết hợp nhiều lớp bảo mật (Hybrid Encryption):
1. Dữ liệu hình ảnh được mã hóa bằng **Data Encryption Key (DEK)** (khóa AES 256-bit sinh ngẫu nhiên cho từng tệp).
2. Khóa DEK được mã hóa bằng **Key Encryption Key (KEK)**.
3. KEK được dẫn xuất từ **(Khóa Phần Cứng + Mã PIN người dùng + Random Salt)** thông qua thuật toán **PBKDF2HMAC** (SHA256, 100.000 vòng lặp).
4. Tính năng chống can thiệp: Mọi hành động chỉnh sửa mã hex hoặc phá hoại file `.enc` đều sẽ bị báo lỗi `InvalidTag` do cơ chế MAC (Message Authentication Code) của AES-GCM.