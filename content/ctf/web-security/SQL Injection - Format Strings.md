---
title: SQL Injection - Format Strings

---

---
title: SQL Injection - Format Strings
---
# Tổng quan
- Lỗ hổng này xảy ra khi dev cố gắng bảo vệ ứng dụng khỏi SQLi bằng cách làm sạch (sanitize) dữ liệu đầu vào (VD: dùng `addslashes` hoặc thay thế ký tự `"`), nhưng sau đó lại đưa dữ liệu đã làm sạch đó vào một hàm định dạng chuỗi (như `printf`, `sprintf`) trước khi gửi xuống `Database`

- Attacker có thể tiêm các Format Specifiers (ký tự đặc tả định dạng như `%s, %c, %d`) vào câu truy vấn để thao túng cấu trúc SQL cuối cùng

# Phân tích nguyên nhân 
**[Theo tài liệu](https://book.jorianwoltjer.com/web/server-side/sql-injection#format-strings)**

- Sanitization: input của người dùng (`username`) được làm sạch các ký tự nguy hiểm (VD: dấu `"` bị escape thành `\"`). Lúc này username được coi là an toàn để nối chuỗi

- Nối chuỗi: input đã làm sạch được nối trực tiếp vào chuỗi query mẫu

- Format String Execution: chuỗi query (đã chứa input của người dùng) được đưa qua một hàm `wrapper` (VD: `mysql_fquery`). Hàm này hoạt động giống `vsprintf`: nó tìm các ký tự `%` để thay thế bằng các tham số 

- The Flaw: nếu người dùng nhập `%c `hoặc `%s` thì hàm `wrapper` sẽ hiểu đó là một chỉ dẫn định dạng chứ không phải dữ liệu thô

# Cơ chế khai thác 
- Mục tiêu là thoát khỏi cặp dấu nháy kép `"` bao quanh `username` để thực thi SQLi. Tuy nhiên thì chúng ta không thể nhập `"` vì nó sẽ bị `filter/escape` ngay từ đầu

- Ta có **"Thuật giả kim ✨"** biến số thành ký tự (`%c`)

## Bước 1 
- chúng ta cần một dấu `"`. Trong bảng mã `ASCII`, ký tự `"` có giá trị thập phân là `34`

## Bước 2 
- Chúng ta nhìn thấy trong query có một tham số khác (VD:  password) được truyền vào hàm định dạng. Giả sử chúng ta kiểm soát được giá trị này hoặc biết nó là gì

## Bước 3 
- Sử dụng "hoán đổi tham số"
- Trong PHP thì `%1$c` nghĩa là: Lấy tham số thứ 1, và định dạng nó dưới dạng ký tự (`char`)

## Bước 4: Payload
- `username`: `%1$c OR 1=1;-- -`
- `password`: `34` (Số `34` dạng chuỗi)

- Điều gì sẽ xảy ra bên trong `vsprintf` 🤔🤨??
- Hàm sẽ quét chuỗi query và khi nó gặp `%1$c`:
    - Nó lấy tham số thứ 1 (là chuỗi `"34"` từ biến `password`)
    - Nó ép kiểu `"34"` thành số nguyên `34`
    - Nó chuyển đổi mã ASCII `34` thành ký tự `"`

=> Dấu `"` được sinh ra bởi chính hệ thống, do đó nó **KHÔNG** bị escape bởi cơ chế lọc đầu vào trước đó
