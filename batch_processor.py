import os
import sys
import csv
import json
import time
import getpass
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# Đảm bảo import được module từ thư mục hiện tại
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import AutoDetectUSBHardwareSecretProvider, SecureImageCryptoEngine

def encrypt_worker(input_path: str, output_path: str, pin: str):
    """
    Hàm thực thi trên từng luồng độc lập. 
    Phải khởi tạo lại Provider và Engine trong mỗi luồng để tránh lỗi Pickling trên Windows.
    """
    provider = AutoDetectUSBHardwareSecretProvider()
    if not provider.is_connected():
        return (input_path, False, "USB bị ngắt kết nối!")
    
    engine = SecureImageCryptoEngine(provider)
    
    # Tạo thư mục con (VD: Day/, Night/) nếu chưa có
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    try:
        engine.encrypt_image(input_path, output_path, pin)
        return (input_path, True, None)
    except Exception as e:
        return (input_path, False, str(e))

def main():
    print("="*60)
    print(" CHƯƠNG TRÌNH MÃ HÓA HÀNG LOẠT DỮ LIỆU LỚN (BATCH ENCRYPTION)")
    print("="*60)
    
    # 1. Cấu hình thư mục
    RAW_DATA_DIR = r"E:\dataset_raw"
    CSV_FILE = os.path.join(RAW_DATA_DIR, "labels_metadata.csv")
    ENC_DATA_DIR = r"E:\dataset_encrypted"
    CHECKPOINT_FILE = os.path.join(ENC_DATA_DIR, "checkpoint.json")
    
    if not os.path.exists(RAW_DATA_DIR) or not os.path.exists(CSV_FILE):
        print(f"[LỖI] Không tìm thấy thư mục {RAW_DATA_DIR} hoặc file {CSV_FILE}.")
        return
        
    os.makedirs(ENC_DATA_DIR, exist_ok=True)
    
    # 2. Kiểm tra phần cứng (USB)
    print("[*] Đang kiểm tra USB khóa phần cứng...")
    provider = AutoDetectUSBHardwareSecretProvider()
    if not provider.is_connected():
        print("[LỖI] CHƯA CẮM USB THẬT (Hoặc USB thiếu tệp 'device_secret.key').")
        print("Vui lòng cắm USB vào và chạy lại script.")
        return
    print(f"[OK] Đã kết nối: {provider.get_device_info()}")
    
    # 3. Yêu cầu nhập PIN (Có thể truyền qua tham số hoặc mặc định 88886666)
    if len(sys.argv) > 1:
        pin = sys.argv[1]
    else:
        try:
            pin = getpass.getpass("Nhập mã PIN của bạn (lưu ý: gõ sẽ không hiện ký tự trên màn hình): ")
        except Exception:
            pin = "88886666"
            
    if not pin:
        pin = "88886666"
    print(f"[*] Sử dụng Mã PIN xác thực: '{pin}'")
    
    # 4. Đọc CSV lấy danh sách ảnh
    print("[*] Đang đọc danh sách ảnh từ CSV...")
    tasks = []
    with open(CSV_FILE, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if not row or len(row) < 4:
                continue
            filename = row[0].strip()
            cam_id = row[1].strip()    # "cam_bayhien", "cam_hangxanh_1"...
            timeslot = row[3].strip()  # "Day" hoặc "Night"
            
            # Cấu trúc thực tế: E:\dataset_raw\<timeslot>\<cam_id>\<filename>
            input_path = os.path.join(RAW_DATA_DIR, timeslot, cam_id, filename)
            output_path = os.path.join(ENC_DATA_DIR, timeslot, cam_id, filename) + ".enc"
            tasks.append((input_path, output_path))
            
    print(f"Tổng số file cần xử lý: {len(tasks)}")
    
    # 5. Tải dữ liệu Checkpoint (Khôi phục tiến trình)
    processed_files = set()
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                checkpoint_data = json.load(f)
                processed_files = set(checkpoint_data.get("processed", []))
            print(f"Đã khôi phục {len(processed_files)} file hoàn thành từ lần chạy trước.")
        except Exception as e:
            print(f"[CẢNH BÁO] Không thể đọc file checkpoint: {e}")
            
    # Lọc bỏ các file đã mã hóa thành công
    pending_tasks = [t for t in tasks if t[0] not in processed_files]
    print(f"Số file còn lại cần mã hóa: {len(pending_tasks)}")
    
    if not pending_tasks:
        print("[OK] Toàn bộ dữ liệu đã được mã hóa xong!")
        return
        
    # 6. Khởi chạy Multiprocessing
    # Để lại 1 core cho hệ điều hành tránh bị giật lag
    num_cores = max(1, multiprocessing.cpu_count() - 1)
    print(f"[*] Bắt đầu tiến trình mã hóa bằng {num_cores} luồng (Tiết kiệm rất nhiều thời gian)...")
    
    start_time = time.time()
    success_count = 0
    fail_count = 0
    
    try:
        with ProcessPoolExecutor(max_workers=num_cores) as executor:
            # Phân phát task cho các luồng
            futures = {executor.submit(encrypt_worker, in_p, out_p, pin): in_p for in_p, out_p in pending_tasks}
            
            for count, future in enumerate(as_completed(futures), 1):
                input_path, success, error_msg = future.result()
                if success:
                    processed_files.add(input_path)
                    success_count += 1
                else:
                    fail_count += 1
                    print(f"\n[LỖI] {input_path} -> {error_msg}")
                
                # In phần trăm tiến độ
                if count % 10 == 0 or count == len(pending_tasks):
                    percent = (count / len(pending_tasks)) * 100
                    print(f"\rTiến độ: {count}/{len(pending_tasks)} ({percent:.2f}%) | Lỗi: {fail_count}", end="", flush=True)
                    
                # Cứ 100 file lưu trạng thái một lần để đề phòng mất điện
                if count % 100 == 0:
                    with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                        json.dump({"processed": list(processed_files)}, f)
                        
    except KeyboardInterrupt:
        print("\n\n[CẢNH BÁO] Hệ thống nhận được lệnh dừng (Ctrl+C). Đang lưu trạng thái hiện tại (Checkpoint)...")
    finally:
        # Cập nhật checkpoint lần cuối trước khi tắt
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump({"processed": list(processed_files)}, f)
            
        elapsed = time.time() - start_time
        print(f"\n\n{'='*60}")
        print(" BÁO CÁO TỔNG KẾT")
        print(f" Thời gian chạy : {elapsed:.2f} giây")
        print(f" Thành công     : {success_count} ảnh")
        print(f" Thất bại       : {fail_count} ảnh")
        print(f" Checkpoint lưu : {CHECKPOINT_FILE}")
        print(f"{'='*60}")

if __name__ == "__main__":
    main()
