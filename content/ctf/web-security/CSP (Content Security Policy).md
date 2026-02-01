---
title: CSP (Content Security Policy)

---

### Giới thiệu về CSP (Content Security Policy)
#### 1. CSP là gì?

- CSP (Content Security Policy) là một cơ chế bảo mật phía client giúp ngăn chặn các tấn công dạng XSS, data injection,..v.v..  bằng cách kiểm soát source mà browser được phép tải và thực thi tài nguyên (scripts, styles, images, frames, fonts, ..v.v..)

- Nói dễ hiểu ra thì là: CSP = Whitelist các nguồn an toàn mà browser được phép dùng

- CSP được triển khai bằng HTTP header hoặc meta tag, thường thấy dưới dạng:

``` java!
Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.google.com; img-src *;
```

#### 2. Mục tiêu của CSP

- CSP được sinh ra để:

  - Ngăn chèn mã độc (malicious script) do XSS.

  - Giới hạn việc tải nội dung từ nguồn không tin cậy.

  - Ngăn kẻ tấn công exfiltrate dữ liệu qua domain bên ngoài.

  - Giảm thiểu thiệt hại nếu trang web bị chèn nội dung.

**Cách hoạt động của CSP**

- Khi trình duyệt nhận được header CSP, nó sẽ:

  - Đọc policy

  - Chặn các tài nguyên không nằm trong danh sách cho phép.

  - Ghi lại các lỗi vi phạm CSP (thường gửi đến `report-uri` hoặc `report-to`).

**Ví dụ:**

``` java!
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net
```

`default-src 'self'`: chỉ cho phép tài nguyên cùng domain

`script-src`: chỉ cho phép chạy JS nội bộ hoặc từ jsDelivr

Nếu hacker cố chèn `<script src="https://evil.com/xss.js"></script>`, trình duyệt sẽ chặn

**CSP và XSS**

 - Không có CSP:

``` html
<input type="text" value="<script>alert(1)</script>">
```
 → Chạy `alert(1)`

 - Có CSP:
``` java
Content-Security-Policy: script-src 'self'
```

 → Browser chặn script inline vì không nằm trong whitelist

CSP là lá chắn XSS thứ hai, sau khi developer đã sanitize input.

**Các directive phổ biến trong CSP**
 - `Directive`: mô tả
 - `default-src`:	nguồn mặc định cho tất cả loại tài nguyên
 - `script-src`:	nguồn được phép cho script
 - `style-src`:	nguồn được phép cho CSS
 - `img-src`:	nguồn được phép cho hình ảnh
 - `font-src`:	nguồn được phép cho font
 - `frame-src`:	nguồn cho iframe
 - `connect-src`:	cho phép kết nối AJAX/WebSocket
 - `report-uri /report-to`:	gửi báo cáo CSP vi phạm

**Ví dụ về 1 CSP mạnh:**
``` java!
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self';
``` 
**CSP LEVEL**

 - CSP Level 1: cơ bản, chỉ whitelist nguồn.

 - CSP Level 2: hỗ trợ nonce & hash.

 - CSP Level 3: thêm strict-dynamic, unsafe-hashes, report-to.

**Nonce & Hash trong CSP**
 - Dành cho các trang cần inline script.
 - Dùng nonce:
``` java!
Content-Security-Policy: script-src 'nonce-h3h3'
<script nonce="h3h3">alert('1');</script>
```

→ Browser chỉ chạy script có đúng nonce hợp lệ.

 - Dùng hash:
``` java
Content-Security-Policy: script-src 'sha256-abcd123...'
```

→ Browser chỉ cho phép chạy inline script có hash khớp.

**Bypass CSP trong CTF/Web Exploitation**

 - Trong CTF, nhiều challenge CSP thường bị cấu hình sai, ví dụ:

  - Cho phép `'unsafe-inline'` → vẫn chạy được `XSS inline`

  - Cho phép `data`: hoặc `blob:` → có thể inject payload JS

  - Cho phép `wildcard *` trong `script-src` → mất tác dụng CSP

  - Chỉ giới hạn `default-src` mà không có `script-src` riêng

Ví dụ bypass:
``` javascript
<script src="https://evil.com/xss.js"></script>
```

Nếu CSP có: `script-src *`; `object-src 'none'`;  → payload vẫn chạy bình thường.

**Cách kiểm tra CSP**

 - Mở `DevTools` → `Console`: xem lỗi `“Refused to load script”`

Trang web online kiểm tra:
https://csp-evaluator.withgoogle.com/
https://report-uri.com/

**Tóm cái quần lại**

 - CSP **không** thay thế việc sanitize input, nhưng nó là lớp bảo vệ mạnh để chống **XSS**, **clickjacking**, và **content injection**



**<CÒN PART 2: Các lỗi cấu hình CSP thường gặp trong CTF>**