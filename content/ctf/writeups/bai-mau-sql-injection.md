---
title: "Giải bài SQL Injection cơ bản"
date: 2026-01-30
tags: ["Web", "SQLi", "CTF"]
---

Đây là bài writeup về cách khai thác lỗi SQL Injection.

## Phân tích
Đoạn code backend đang nối chuỗi trực tiếp:

```python
# Ví dụ code Python dễ bị lỗi
query = "SELECT * FROM users WHERE username = '" + user_input + "'"