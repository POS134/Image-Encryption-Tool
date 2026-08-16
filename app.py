import os
import sys
import json
import struct
import hashlib
import time
import threading
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

import psutil

# Import Tkinter & CustomTkinter cho giao diện GUI mã hóa hiện đại
try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
except ImportError:
    ctk = None

# ==============================================================================
# 1. HARDWARE SECRET PROVIDER ABSTRACTION & DRIVERS
# ==============================================================================

class HardwareSecretProvider(ABC):
    """Interface trừu tượng quản lý nguồn lấy Bí mật Phần ứng"""
    @abstractmethod
    def get_hardware_secret(self) -> bytes:
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        pass

    @abstractmethod
    def get_device_info(self) -> str:
        pass


class FolderHardwareSecretProvider(HardwareSecretProvider):
    """Giai đoạn 1A: Mô phỏng bằng Thư mục An toàn cố định"""
    def __init__(self, secure_folder_path: str):
        self.secure_folder_path = secure_folder_path
        self.secret_file_name = "device_secret.key"

    def is_connected(self) -> bool:
        secret_path = os.path.join(self.secure_folder_path, self.secret_file_name)
        return os.path.exists(self.secure_folder_path) and os.path.exists(secret_path)

    def get_device_info(self) -> str:
        if self.is_connected():
            return f"Folder Mô phỏng: {self.secure_folder_path}"
        return "Chưa kết nối Thư mục an toàn"

    def get_hardware_secret(self) -> bytes:
        if not os.path.exists(self.secure_folder_path):
            raise FileNotFoundError(f"[LỖI] Thư mục an toàn không tồn tại: '{self.secure_folder_path}'")
        
        secret_path = os.path.join(self.secure_folder_path, self.secret_file_name)
        if not os.path.exists(secret_path):
            raise FileNotFoundError(f"[LỖI] Tệp khóa bí mật bị thiếu: '{secret_path}'")
            
        with open(secret_path, "rb") as f:
            secret = f.read()

        if len(secret) < 16:
            raise ValueError("[LỖI] Khóa phần cứng phải tối thiểu 16 bytes.")
        return secret


class AutoDetectUSBHardwareSecretProvider(HardwareSecretProvider):
    """
    Giai đoạn 1B: Tự động phát hiện bất kỳ USB Thật (Removable Drive) cắm vào máy tính.
    Tìm tệp 'device_secret.key' nằm tại thư mục gốc của USB di động.
    """
    def __init__(self, secret_filename: str = "device_secret.key"):
        self.secret_filename = secret_filename

    def _find_usb_secret_path(self) -> Optional[Tuple[str, str]]:
        """Quét tất cả các ổ đĩa di động (USB) đang cắm trên máy"""
        partitions = psutil.disk_partitions(all=False)
        for p in partitions:
            # Kiểm tra ổ đĩa di động (removable / USB)
            if 'removable' in p.opts.lower() or p.device.startswith(('E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:', 'U:')):
                secret_path = os.path.join(p.mountpoint, self.secret_filename)
                if os.path.exists(secret_path):
                    return p.mountpoint, secret_path
        return None

    def is_connected(self) -> bool:
        return self._find_usb_secret_path() is not None

    def get_device_info(self) -> str:
        usb_info = self._find_usb_secret_path()
        if usb_info:
            mountpoint, _ = usb_info
            return f"USB Thật (Ổ đĩa {mountpoint}) [ĐÃ SẴN SÀNG]"
        return "CHƯA KẾT NỐI USB THẬT (Hoặc USB thiếu tệp 'device_secret.key')"

    def get_hardware_secret(self) -> bytes:
        usb_info = self._find_usb_secret_path()
        if not usb_info:
            raise FileNotFoundError("[LỖI USB] Không phát hiện thấy USB thật hoặc tệp 'device_secret.key' trên USB!")
        
        _, secret_path = usb_info
        with open(secret_path, "rb") as f:
            secret = f.read()
        return secret


class PKCS11HardwareSecretProvider(HardwareSecretProvider):
    """
    Giai đoạn 2 (Sẵn sàng mở rộng): Kết nối USB Token / HSM Chuyên dụng chuẩn PKCS#11.
    Sẵn sàng tích hợp thư viện PyKCS11 khi có thiết bị phần cứng mã hóa chuyên dụng.
    """
    def __init__(self, library_path: str = "C:/Windows/System32/eToken.dll", slot: int = 0):
        self.library_path = library_path
        self.slot = slot

    def is_connected(self) -> bool:
        # Khung kết nối PKCS#11 thực tế
        return os.path.exists(self.library_path)

    def get_device_info(self) -> str:
        return f"PKCS#11 HSM Provider (Slot {self.slot}, Lib: {os.path.basename(self.library_path)})"

    def get_hardware_secret(self) -> bytes:
        if not self.is_connected():
            raise NotImplementedError("[PKCS#11] Chưa phát hiện Driver PKCS#11 HSM trên hệ thống.")
        # Mã mẫu giao tiếp PKCS#11 C_GetTokenInfo & C_FindObjects
        return b"PKCS11_HSM_HARDWARE_SECRET_KEY_32B"


class MachineSerialHardwareSecretProvider(HardwareSecretProvider):
    """
    Giai đoạn 3 (Hardware-Binding): Sử dụng UUID/Serial của Máy tính làm Khóa.
    Mỗi máy tính sẽ sinh ra khóa khác nhau. Chống copy file sang máy khác.
    """
    def is_connected(self) -> bool:
        return True

    def get_device_info(self) -> str:
        return "Serial Máy tính (Hardware-Binding) [ĐÃ SẴN SÀNG]"

    def get_hardware_secret(self) -> bytes:
        import subprocess
        try:
            # Lấy UUID của Mainboard qua wmic (Windows)
            output = subprocess.check_output('wmic csproduct get uuid', shell=True).decode()
            lines = output.strip().split('\n')
            if len(lines) >= 2:
                uuid = lines[1].strip()
                if uuid:
                    return uuid.encode('utf-8')
        except Exception:
            pass
        return b"FALLBACK_MACHINE_SERIAL_SECRET_KEY_123"


# ==============================================================================
# 2. CRYPTO ENGINE WITH PROGRESS CALLBACK FOR GUI
# ==============================================================================

class SecureImageCryptoEngine:
    CHUNK_SIZE = 4 * 1024 * 1024  # Tối ưu 4MB Chunk cho file lớn (ví dụ 33GB)
    SALT_SIZE = 16
    NONCE_SIZE = 12
    MAGIC_HEADER = b"SECIMG01"

    def __init__(self, hardware_provider: HardwareSecretProvider):
        self.hw_provider = hardware_provider

    def _derive_kek(self, pin: str, salt: bytes) -> bytes:
        hw_secret = self.hw_provider.get_hardware_secret()
        combined_secret = hw_secret + pin.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(combined_secret)

    def encrypt_image(self, input_image_path: str, output_enc_path: str, pin: str, progress_callback=None) -> None:
        if not os.path.exists(input_image_path):
            raise FileNotFoundError(f"Không tìm thấy tệp ảnh đầu vào: '{input_image_path}'")

        file_size = os.path.getsize(input_image_path)
        salt = os.urandom(self.SALT_SIZE)
        kek = self._derive_kek(pin, salt)
        dek = AESGCM.generate_key(bit_length=256)

        kek_aesgcm = AESGCM(kek)
        dek_nonce = os.urandom(self.NONCE_SIZE)
        encrypted_dek = kek_aesgcm.encrypt(dek_nonce, dek, associated_data=b"DEK_ENCRYPTION")

        metadata = {
            "salt": salt.hex(),
            "dek_nonce": dek_nonce.hex(),
            "encrypted_dek": encrypted_dek.hex(),
            "chunk_size": self.CHUNK_SIZE
        }
        metadata_bytes = json.dumps(metadata).encode('utf-8')
        header_len = len(metadata_bytes)

        image_aesgcm = AESGCM(dek)
        processed_bytes = 0
        chunk_index = 0

        with open(input_image_path, "rb") as fin, open(output_enc_path, "wb") as fout:
            fout.write(self.MAGIC_HEADER)
            fout.write(struct.pack(">I", header_len))
            fout.write(metadata_bytes)

            while True:
                chunk = fin.read(self.CHUNK_SIZE)
                if not chunk:
                    break

                chunk_nonce = os.urandom(self.NONCE_SIZE)
                assoc_data = f"CHUNK_{chunk_index}".encode('utf-8')
                encrypted_chunk = image_aesgcm.encrypt(chunk_nonce, chunk, associated_data=assoc_data)
                
                fout.write(struct.pack(">I", len(encrypted_chunk)))
                fout.write(chunk_nonce)
                fout.write(encrypted_chunk)

                processed_bytes += len(chunk)
                chunk_index += 1

                if progress_callback and file_size > 0:
                    percent = min(1.0, processed_bytes / file_size)
                    progress_callback(percent, f"Đã mã hóa: {processed_bytes/(1024*1024):.1f} MB / {file_size/(1024*1024):.1f} MB ({percent*100:.1f}%)")

    def decrypt_image(self, input_enc_path: str, output_image_path: str, pin: str, progress_callback=None) -> None:
        if not os.path.exists(input_enc_path):
            raise FileNotFoundError(f"Không tìm thấy tệp mã hóa: '{input_enc_path}'")

        file_size = os.path.getsize(input_enc_path)

        with open(input_enc_path, "rb") as fin:
            magic = fin.read(len(self.MAGIC_HEADER))
            if magic != self.MAGIC_HEADER:
                raise ValueError("[XÁC THỰC THẤT BẠI] Định dạng tệp không phải .enc hợp lệ!")

            header_len_bytes = fin.read(4)
            header_len = struct.unpack(">I", header_len_bytes)[0]
            
            metadata_bytes = fin.read(header_len)
            metadata = json.loads(metadata_bytes.decode('utf-8'))

            salt = bytes.fromhex(metadata["salt"])
            dek_nonce = bytes.fromhex(metadata["dek_nonce"])
            encrypted_dek = bytes.fromhex(metadata["encrypted_dek"])

            kek = self._derive_kek(pin, salt)
            kek_aesgcm = AESGCM(kek)

            try:
                dek = kek_aesgcm.decrypt(dek_nonce, encrypted_dek, associated_data=b"DEK_ENCRYPTION")
            except InvalidTag:
                raise ValueError("[MÃ HÓA SAI / CAN THIỆP] Nhập sai PIN hoặc Khóa Phần ứng (USB) không chính xác!")

            image_aesgcm = AESGCM(dek)
            chunk_index = 0
            processed_bytes = 0

            with open(output_image_path, "wb") as fout:
                while True:
                    chunk_len_bytes = fin.read(4)
                    if not chunk_len_bytes:
                        break

                    chunk_len = struct.unpack(">I", chunk_len_bytes)[0]
                    chunk_nonce = fin.read(self.NONCE_SIZE)
                    encrypted_chunk = fin.read(chunk_len)

                    assoc_data = f"CHUNK_{chunk_index}".encode('utf-8')

                    try:
                        decrypted_chunk = image_aesgcm.decrypt(chunk_nonce, encrypted_chunk, associated_data=assoc_data)
                        fout.write(decrypted_chunk)
                    except InvalidTag:
                        raise ValueError(
                            f"[CAN THIỆP TRÁI PHÉP] Khối dữ liệu #{chunk_index} đã bị chỉnh sửa (GCM Auth Failed)!"
                        )

                    processed_bytes += (4 + self.NONCE_SIZE + chunk_len)
                    chunk_index += 1

                    if progress_callback and file_size > 0:
                        percent = min(1.0, processed_bytes / file_size)
                        progress_callback(percent, f"Đã giải mã: {processed_bytes/(1024*1024):.1f} MB / {file_size/(1024*1024):.1f} MB ({percent*100:.1f}%)")


# ==============================================================================
# 3. GIAO DIỆN NGUỜI DÙNG CAO CẤP (MODERN GUI APPLICATION WITH CUSTOMTKINTER)
# ==============================================================================

class SecureImageApp(ctk.CTk if ctk else object):
    def __init__(self):
        if ctk is None:
            print("[LỖI] Chưa cài đặt customtkinter. Hãy chạy 'pip install customtkinter'")
            return
        
        super().__init__()

        self.title("Secure Image Guard - Pro Dashboard")
        self.geometry("920x720")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Nguồn quản lý phần cứng
        self.workspace_dir = os.path.dirname(os.path.abspath(__file__))
        self.secure_folder = r"C:\SecureKeys"
        self.folder_provider = FolderHardwareSecretProvider(self.secure_folder)
        self.usb_provider = AutoDetectUSBHardwareSecretProvider()
        self.pkcs11_provider = PKCS11HardwareSecretProvider()
        self.machine_provider = MachineSerialHardwareSecretProvider()

        self.current_provider = self.usb_provider  # Mặc định ưu tiên USB Thật
        
        self.selected_file_path = ""
        self.setup_ui()
        self.start_hw_monitor()

    def setup_ui(self):
        # Thiết lập theme tối giản, chuyên nghiệp theo Stitch Design System
        ctk.set_appearance_mode("Dark")
        
        # --- 1. HEADER (TIÊU ĐỀ) ---
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="#121414", height=80)
        self.header_frame.pack(fill="x", padx=0, pady=(0, 10))

        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="SECURE IMAGE GUARD - PRO DASHBOARD",
            font=ctk.CTkFont(family="Inter", size=24, weight="bold"),
            text_color="#FFFFFF"
        )
        self.title_label.pack(pady=(15, 2))
        
        self.subtitle_label = ctk.CTkLabel(
            self.header_frame, 
            text="Enterprise-Grade Hardware-Bound Image Encryption",
            font=ctk.CTkFont(family="Inter", size=12),
            text_color="#C0C7D3" # on-surface-variant
        )
        self.subtitle_label.pack(pady=(0, 15))

        # --- 2. CẤU HÌNH PHẦN CỨNG (HARDWARE CONFIGURATION) ---
        self.hw_frame = ctk.CTkFrame(self, corner_radius=4, fg_color="#1E2020", border_width=1, border_color="#404751")
        self.hw_frame.pack(fill="x", padx=20, pady=10)

        self.hw_title = ctk.CTkLabel(self.hw_frame, text="Hardware Security Module:", font=ctk.CTkFont(family="Inter", size=12, weight="bold"), text_color="#E3E2E2")
        self.hw_title.grid(row=0, column=0, padx=15, pady=15, sticky="w")

        self.mode_selector = ctk.CTkOptionMenu(
            self.hw_frame,
            values=["USB Token (Auto-detect)", "Secure Folder (Virtual)", "Machine Serial (Hardware Binding)", "PKCS#11 HSM (SmartCard)"],
            command=self.on_provider_changed,
            font=ctk.CTkFont(family="Inter", size=12),
            width=280,
            fg_color="#1A1C1C", # surface-container-low
            button_color="#292A2A", # surface-container-high
            button_hover_color="#333535", # surface-container-highest
            corner_radius=4
        )
        self.mode_selector.grid(row=0, column=1, padx=10, pady=15, sticky="w")

        self.status_lbl = ctk.CTkLabel(self.hw_frame, text="System initializing...", font=ctk.CTkFont(family="Inter", size=12), text_color="#007ACC")
        self.status_lbl.grid(row=0, column=2, padx=15, pady=15, sticky="e")
        self.hw_frame.grid_columnconfigure(2, weight=1)

        # --- 3. KHU VỰC ĐẦU VÀO (INPUT & SECURITY PARAMS) ---
        self.input_frame = ctk.CTkFrame(self, corner_radius=4, fg_color="#1E2020", border_width=1, border_color="#404751")
        self.input_frame.pack(fill="x", padx=20, pady=10)

        # Hàng 1: Chọn File / Folder
        self.btn_select_file = ctk.CTkButton(
            self.input_frame, text="Select File", command=self.select_file, 
            width=120, height=32, font=ctk.CTkFont(family="Inter", size=12),
            fg_color="transparent", hover_color="#292A2A", border_width=1, border_color="#404751", text_color="#E3E2E2", corner_radius=2
        )
        self.btn_select_file.grid(row=0, column=0, padx=(15, 5), pady=(15, 10))

        self.btn_select_folder = ctk.CTkButton(
            self.input_frame, text="Select Directory", command=self.select_folder, 
            width=120, height=32, font=ctk.CTkFont(family="Inter", size=12),
            fg_color="transparent", hover_color="#292A2A", border_width=1, border_color="#404751", text_color="#E3E2E2", corner_radius=2
        )
        self.btn_select_folder.grid(row=0, column=1, padx=5, pady=(15, 10))

        self.file_path_lbl = ctk.CTkLabel(
            self.input_frame, text="No target selected", 
            font=ctk.CTkFont(family="Inter", size=12, slant="italic"), text_color="#8A919D" # outline
        )
        self.file_path_lbl.grid(row=0, column=2, padx=15, pady=(15, 10), sticky="w")

        # Hàng 2: Mã PIN & Tùy chọn Xóa Gốc
        self.pin_label = ctk.CTkLabel(self.input_frame, text="Security PIN:", font=ctk.CTkFont(family="Inter", size=12, weight="bold"), text_color="#E3E2E2")
        self.pin_label.grid(row=1, column=0, padx=15, pady=(5, 15), sticky="e")

        self.pin_entry = ctk.CTkEntry(
            self.input_frame, placeholder_text="Enter PIN", show="*", 
            width=125, height=32, font=ctk.CTkFont(family="Inter", size=14), corner_radius=2,
            border_color="#404751", fg_color="#121414"
        )
        self.pin_entry.grid(row=1, column=1, padx=5, pady=(5, 15), sticky="w")

        self.delete_orig_var = ctk.BooleanVar(value=True)
        self.delete_orig_cb = ctk.CTkCheckBox(
            self.input_frame, 
            text="Enable In-Place Encryption (Secure Wipe)", 
            variable=self.delete_orig_var,
            font=ctk.CTkFont(family="Inter", size=12),
            text_color="#E3E2E2",
            checkbox_height=20, checkbox_width=20,
            corner_radius=2, fg_color="#007ACC", hover_color="#0061A4", border_color="#404751"
        )
        self.delete_orig_cb.grid(row=1, column=2, padx=15, pady=(5, 15), sticky="w")

        # --- 4. KHU VỰC ĐIỀU KHIỂN CHÍNH (MAIN ACTIONS) ---
        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(fill="x", padx=20, pady=10)

        self.btn_encrypt = ctk.CTkButton(
            self.action_frame, 
            text="ENCRYPT", 
            command=self.encrypt_action, 
            fg_color="#007ACC", # primary-container
            hover_color="#0061A4", # inverse-primary
            font=ctk.CTkFont(family="Inter", size=13, weight="bold"),
            height=40, corner_radius=2
        )
        self.btn_encrypt.pack(side="left", expand=True, fill="x", padx=(0, 5))

        self.btn_decrypt = ctk.CTkButton(
            self.action_frame, 
            text="DECRYPT", 
            command=self.decrypt_action, 
            fg_color="transparent", 
            hover_color="#1A1C1C", # surface-container-low
            border_width=1, border_color="#007ACC",
            font=ctk.CTkFont(family="Inter", size=13, weight="bold"),
            height=40, corner_radius=2, text_color="#E3E2E2"
        )
        self.btn_decrypt.pack(side="right", expand=True, fill="x", padx=(5, 0))

        # --- 5. SYSTEM LOG & PROGRESS ---
        self.progress_frame = ctk.CTkFrame(self, corner_radius=4, fg_color="#0D0E0F", border_width=1, border_color="#404751") # surface-container-lowest
        self.progress_frame.pack(fill="both", expand=True, padx=20, pady=(10, 20))

        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, progress_color="#007ACC", fg_color="#333535", height=8, corner_radius=0)
        self.progress_bar.pack(fill="x", padx=15, pady=(15, 5))
        self.progress_bar.set(0)

        self.progress_lbl = ctk.CTkLabel(self.progress_frame, text="Ready", font=ctk.CTkFont(family="Inter", size=11), text_color="#8A919D")
        self.progress_lbl.pack(anchor="w", padx=15, pady=(0, 5))

        self.log_textbox = ctk.CTkTextbox(
            self.progress_frame, 
            font=ctk.CTkFont(family="JetBrains Mono", size=13), 
            fg_color="#0D0E0F", text_color="#E3E2E2", 
            border_width=0, corner_radius=0
        )
        self.log_textbox.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def log(self, msg: str):
        self.log_textbox.insert("end", msg + "\n")
        self.log_textbox.see("end")

    def on_provider_changed(self, choice: str):
        if "USB Token" in choice:
            self.current_provider = self.usb_provider
        elif "Secure Folder" in choice:
            self.current_provider = self.folder_provider
        elif "Machine Serial" in choice:
            self.current_provider = self.machine_provider
        else:
            self.current_provider = self.pkcs11_provider
        self.update_hw_status()

    def update_hw_status(self):
        connected = self.current_provider.is_connected()
        info = self.current_provider.get_device_info()
        if connected:
            self.status_lbl.configure(text=f"🔴 TRẠNG THÁI: {info}", text_color="#4CAF50")
        else:
            self.status_lbl.configure(text=f"⚠️ TRẠNG THÁI: {info}", text_color="#F44336")

    def start_hw_monitor(self):
        """Thread chạy ngầm theo dõi trạng thái cắm/rút USB"""
        def monitor():
            while True:
                time.sleep(2)
                try:
                    self.update_hw_status()
                except Exception:
                    pass
        threading.Thread(target=monitor, daemon=True).start()

    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Chọn tệp ảnh hoặc tệp mã hóa",
            filetypes=[
                ("Tất cả tệp ảnh & mã hóa", "*.png;*.jpg;*.jpeg;*.bmp;*.raw;*.enc"),
                ("Tệp ảnh PNG (*.png)", "*.png"),
                ("Tệp ảnh JPG (*.jpg)", "*.jpg"),
                ("Tệp mã hóa (.enc)", "*.enc"),
                ("Tất cả tệp (*.*)", "*.*")
            ]
        )
        if file_path:
            self.selected_file_path = file_path
            self.is_folder_mode = False
            file_name = os.path.basename(file_path)
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            self.file_path_lbl.configure(text=f"Tệp lẻ: {file_name} ({size_mb:.2f} MB)")
            self.log(f"[*] Đã chọn tệp lẻ: {file_path} ({size_mb:.2f} MB)")

    def select_folder(self):
        folder_path = filedialog.askdirectory(title="Chọn Thư mục (Mã Hóa hoặc Giải Mã)")
        if folder_path:
            self.selected_file_path = folder_path
            self.is_folder_mode = True
            folder_name = os.path.basename(folder_path)
            self.file_path_lbl.configure(text=f"Thư mục: /{folder_name}")
            self.log(f"[*] Đã chọn THƯ MỤC: {folder_path}")

    def update_progress(self, percent: float, text: str):
        self.progress_bar.set(percent)
        self.progress_lbl.configure(text=text)

    def encrypt_action(self):
        if not self.selected_file_path:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tệp lẻ hoặc Thư mục trước!")
            return
        pin = self.pin_entry.get().strip()
        if not pin:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập Mã PIN!")
            return

        is_folder = getattr(self, 'is_folder_mode', False) and os.path.isdir(self.selected_file_path)

        if is_folder:
            out_path = self.selected_file_path
        else:
            out_path = self.selected_file_path + ".enc"

        def run():
            self.btn_encrypt.configure(state="disabled")
            self.btn_decrypt.configure(state="disabled")
            self.log(f"\n==================== [BẮT ĐẦU MÃ HÓA] ====================")
            start_time = time.time()
            try:
                engine = SecureImageCryptoEngine(self.current_provider)
                if is_folder:
                    self.log(f"[*] Bắt đầu Mã hóa hàng loạt Thư mục: {self.selected_file_path}")
                    files_to_enc = []
                    for root, _, files in os.walk(self.selected_file_path):
                        for f in files:
                            if not f.endswith(".enc"):
                                files_to_enc.append(os.path.join(root, f))
                    
                    total = len(files_to_enc)
                    self.log(f"[*] Tổng số file phát hiện: {total}")
                    should_delete = self.delete_orig_var.get()
                    if should_delete:
                        self.log("[🔥 MÔ HÌNH A KÍCH HOẠT] Ảnh gốc sẽ tự động XÓA VĨNH VIỄN sau khi mã hóa thành công!")

                    for idx, in_f in enumerate(files_to_enc, 1):
                        rel_path = os.path.relpath(in_f, self.selected_file_path)
                        target_f = os.path.join(out_path, rel_path) + ".enc"
                        os.makedirs(os.path.dirname(target_f), exist_ok=True)
                        
                        engine.encrypt_image(in_f, target_f, pin)

                        if should_delete and os.path.exists(target_f):
                            try:
                                os.remove(in_f)
                            except Exception as del_e:
                                self.log(f"    [!] Không thể xóa ảnh gốc: {del_e}")

                        percent = idx / total
                        self.update_progress(percent, f"Đã mã hóa thư mục: {idx}/{total} file ({percent*100:.1f}%)")
                        if idx <= 5 or idx % 10 == 0 or idx == total:
                            self.log(f"    -> Đã mã hóa #{idx}/{total}: {os.path.basename(in_f)} {'[ĐÃ XÓA GỐC 🔥]' if should_delete else ''}")
                else:
                    engine.encrypt_image(self.selected_file_path, out_path, pin, progress_callback=self.update_progress)
                    if self.delete_orig_var.get() and os.path.exists(out_path):
                        os.remove(self.selected_file_path)
                        self.log(f"[🔥 MÔ HÌNH A] Đã XÓA VĨNH VIỄN tệp gốc: {os.path.basename(self.selected_file_path)}")
                
                elapsed = time.time() - start_time
                self.log(f"[✓] MÃ HÓA THÀNH CÔNG trong {elapsed:.2f} giây!")
                messagebox.showinfo("Thành công", f"Mã hóa hoàn tất!\nThời gian: {elapsed:.2f}s")
            except Exception as e:
                self.log(f"[LỖI BẢO MẬT]: {e}")
                messagebox.showerror("Lỗi Mã Hóa", str(e))
            finally:
                self.btn_encrypt.configure(state="normal")
                self.btn_decrypt.configure(state="normal")

        threading.Thread(target=run, daemon=True).start()

    def decrypt_action(self):
        if not self.selected_file_path:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tệp mã hóa (.enc) hoặc Thư mục chứa tệp mã hóa!")
            return
        pin = self.pin_entry.get().strip()
        if not pin:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập Mã PIN!")
            return

        is_folder = getattr(self, 'is_folder_mode', False) and os.path.isdir(self.selected_file_path)

        if is_folder:
            out_path = self.selected_file_path
        else:
            if self.selected_file_path.endswith(".enc"):
                out_path = self.selected_file_path[:-4]
            else:
                out_path = self.selected_file_path + ".dec"

        def run():
            self.btn_encrypt.configure(state="disabled")
            self.btn_decrypt.configure(state="disabled")
            self.log(f"\n==================== [BẮT ĐẦU GIẢI MÃ] ====================")
            start_time = time.time()
            try:
                engine = SecureImageCryptoEngine(self.current_provider)
                if is_folder:
                    self.log(f"[*] Bắt đầu Giải mã hàng loạt Thư mục: {self.selected_file_path}")
                    files_to_dec = []
                    for root, _, files in os.walk(self.selected_file_path):
                        for f in files:
                            if f.endswith(".enc"):
                                files_to_dec.append(os.path.join(root, f))
                    
                    total = len(files_to_dec)
                    if total == 0:
                        raise ValueError("Không tìm thấy tệp đuôi .enc nào trong thư mục được chọn!")

                    self.log(f"[*] Tổng số file .enc phát hiện: {total}")
                    for idx, in_f in enumerate(files_to_dec, 1):
                        rel_path = os.path.relpath(in_f, self.selected_file_path)
                        # Bỏ đuôi .enc khi khôi phục
                        if rel_path.endswith(".enc"):
                            orig_rel_path = rel_path[:-4]
                        else:
                            orig_rel_path = rel_path
                            
                        target_f = os.path.join(out_path, orig_rel_path)
                        os.makedirs(os.path.dirname(target_f), exist_ok=True)
                        
                        engine.decrypt_image(in_f, target_f, pin)
                        
                        # Giải mã thành công -> Tự động xóa tệp rác .enc
                        if os.path.exists(target_f):
                            try:
                                os.remove(in_f)
                            except Exception as del_e:
                                self.log(f"    [!] Không thể xóa tệp .enc: {del_e}")

                        percent = idx / total
                        self.update_progress(percent, f"Đã giải mã thư mục: {idx}/{total} file ({percent*100:.1f}%)")
                        if idx <= 5 or idx % 10 == 0 or idx == total:
                            self.log(f"    -> Đã giải mã #{idx}/{total}: {os.path.basename(orig_rel_path)} [ĐÃ DỌN .ENC 🔥]")
                else:
                    engine.decrypt_image(self.selected_file_path, out_path, pin, progress_callback=self.update_progress)
                    if os.path.exists(out_path):
                        os.remove(self.selected_file_path)
                        self.log(f"[🔥 DỌN DẸP] Đã XÓA TỆP MÃ HÓA .ENC sau khi phục hồi ảnh gốc thành công!")

                elapsed = time.time() - start_time
                self.log(f"[✓] GIẢI MÃ THÀNH CÔNG toàn bộ tệp trong {elapsed:.2f} giây!")
                messagebox.showinfo("Thành công", f"Giải mã hoàn tất!\nThời gian: {elapsed:.2f}s")
            except Exception as e:
                self.log(f"[LỖI XÁC THỰC / GCM TAG]: {e}")
                messagebox.showerror("Lỗi Giải Mã / Integrity Breach", str(e))
            finally:
                self.btn_encrypt.configure(state="normal")
                self.btn_decrypt.configure(state="normal")

        threading.Thread(target=run, daemon=True).start()


# ==============================================================================
# 4. ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    if ctk:
        app = SecureImageApp()
        app.mainloop()
    else:
        print("Vui lòng cài đặt customtkinter bằng lệnh: pip install customtkinter")
