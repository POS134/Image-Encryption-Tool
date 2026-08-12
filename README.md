# HỆ THỐNG MÃ HÓA & LƯU TRỮ ẢNH AN TOÀN (Image-Encryption-Tool)

Dự án này là hệ thống phần mềm hỗ trợ mã hóa và giải mã hình ảnh/dữ liệu an toàn, được phát triển phục vụ cho Đồ án/Luận văn Thạc sĩ. Hệ thống giải quyết bài toán lưu trữ Dữ liệu lớn (Big Data) trên các thiết bị di động (USB/Ổ cứng ngoài) bằng cách áp dụng mô hình **Mã hóa Phong bì (Envelope Encryption)** kết hợp với **Trói buộc Phần cứng (Hardware-Binding)**, đảm bảo an toàn tuyệt đối chống lại rủi ro mất cắp thiết bị lưu trữ.

## Kiến trúc Bảo mật (Cốt lõi Luận văn)

Hệ thống tách biệt hoàn toàn **Nơi lưu trữ dữ liệu (USB)** và **Khóa giải mã (Máy tính)** thông qua kiến trúc 2 tầng khóa:

1. **Khóa Dữ liệu (DEK - Data Encryption Key):** 
   Mỗi tệp được mã hóa bằng một khóa ngẫu nhiên chuẩn **AES-256-GCM**. Thuật toán này có tốc độ cực cao, phù hợp để xử lý các tệp dataset khổng lồ, đồng thời cung cấp tính năng Xác thực thông điệp (GCM Auth Tag) giúp chống lại các hành vi can thiệp hay phá hoại dữ liệu (Ransomware).
2. **Khóa Bảo vệ Khóa (KEK - Key Encryption Key):**
   Khóa DEK sẽ được mã hóa và đóng gói lại bởi khóa KEK. Khóa KEK không được lưu trữ mà được dẫn xuất động (PBKDF2HMAC) từ sự kết hợp của 2 yếu tố (2FA):
   - **Yếu tố con người (Mã PIN):** Mật khẩu bí mật của người dùng.
   - **Yếu tố phần cứng (Hardware Key):** Hệ thống trích xuất **Mã Serial / UUID của Bo mạch chủ (Máy tính)** làm chìa khóa.

**Kịch bản Ứng dụng Thực tế:** Toàn bộ dữ liệu mã hóa được lưu trên USB. Người dùng có thể đánh rơi USB mà không sợ lộ dữ liệu, vì kẻ gian dù biết mã PIN cũng không thể mở được file do không có đúng chiếc Máy tính (Khóa phần cứng) của nạn nhân.

## Tính năng nổi bật
* **Bảo mật Hardware-Binding:** Chống đánh cắp dữ liệu chéo thiết bị bằng cách neo khóa mã hóa vào phần cứng máy tính hoặc Smartcard.
* **Xử lý Streaming (Chunking):** Tối ưu hóa RAM cho các tệp ảnh/dữ liệu cực lớn (hỗ trợ đến 33GB+) bằng cách chia nhỏ dữ liệu thành các khối 4MB để xử lý "in-flight" thay vì nạp toàn bộ vào RAM.
* **Giao diện hiện đại (GUI):** Ứng dụng tích hợp giao diện người dùng hiện đại, thân thiện Dark Mode, được xây dựng bằng `customtkinter`.
* **Xử lý Hàng loạt (Batch Processing):** Hỗ trợ mã hóa hàng loạt dataset bằng đa tiến trình (Multiprocessing), tích hợp tính năng tự động lưu điểm neo (`checkpoint.json`) để khôi phục khi bị gián đoạn.
* **Công cụ Báo cáo Trực quan:** Chứa script tự động tạo biểu đồ so sánh hiệu suất tiêu thụ RAM và tốc độ xử lý phục vụ báo cáo khoa học.

## Cấu trúc Dự án
* `main.py`: Chứa ứng dụng GUI chính, bộ công cụ mã hóa lõi, và các lớp quản lý giao tiếp thiết bị (USB, Thư mục mô phỏng, Serial Máy tính, PKCS#11).
* `batch_encrypt.py`: Script CLI mã hóa hàng loạt tối đa hóa công suất CPU.
* `generate_charts.py`: Script xuất các biểu đồ trực quan (benchmark tốc độ và RAM) phục vụ viết luận văn.

## Hướng dẫn Sử dụng

### 1. Khởi chạy Ứng dụng Chính
```bash
python main.py
```
* **Mã hóa:** Chọn nguồn khóa là **Serial Máy Tính (Hardware-Binding)**. Chọn thư mục chứa dataset ảnh, nhập PIN và trỏ đầu ra trực tiếp vào USB/Ổ cứng ngoài.
* **Giải mã:** Cắm USB vào đúng chiếc máy tính đã mã hóa, chọn file trên USB, nhập PIN để giải mã.

### 2. Mã hóa Hàng loạt (Batch Processing)
Phù hợp để xử lý toàn bộ dataset. Tự động khai thác đa luồng CPU:
```bash
python batch_encrypt.py
```
*(Lưu ý: Tinh chỉnh đường dẫn Input/Output trong file script trước khi chạy).*

### 3. Xuất Biểu đồ Đánh giá
```bash
python generate_charts.py
```
*(Biểu đồ sẽ được lưu ở thư mục `report_charts/`).*