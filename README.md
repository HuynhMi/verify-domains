# verify-domains — Placement Labeler

Công cụ lọc website quảng cáo (Google Ads placements). Nhập danh sách domain hoặc tải
file Excel/CSV → tool mở từng trang, tra tuổi tên miền, dò từ khoá xấu → gắn nhãn
**BLOCK / REVIEW / KEEP** và xuất file kết quả.

Cách kiểm tra và giới hạn của từng tầng được ghi ngay trong giao diện, mục
*"🔍 Tool kiểm tra bằng cách nào — và tin được đến đâu"*.

## Chạy trên máy (local)

Cần Python 3.9+.

```bash
pip install -r requirements.txt
python placement_web.py
```

Tool tự mở trình duyệt ở `http://127.0.0.1:8000`. Đóng cửa sổ terminal để tắt.

## Chạy trên web (Render — miễn phí)

GitHub Pages **không** chạy được vì đây là Python server. Dùng Render:

1. Đăng nhập <https://render.com> bằng tài khoản GitHub.
2. **New → Web Service** → chọn repo `verify-domains`.
3. Render tự đọc `render.yaml`: runtime Python, build `pip install -r requirements.txt`,
   start `python placement_web.py`. Bấm **Deploy**.
4. Vài phút sau có link công khai dạng `https://verify-domains.onrender.com`.

Server tự đọc biến môi trường `PORT` và bind `0.0.0.0` khi chạy trên host.

### Đặt mật khẩu (nên làm khi để public)

Link Render mặc định ai có cũng vào được. Bật mật khẩu bằng cách thêm biến môi trường
trong **Render → service → Environment**:

| Key | Value |
|-----|-------|
| `APP_PASSWORD` | mật khẩu bạn chọn (bắt buộc để bật) |
| `APP_USER` | tên đăng nhập (tuỳ chọn, mặc định `team`) |

Sau khi đặt, trình duyệt sẽ hỏi đăng nhập trước khi vào tool. **Không đặt** thì tool mở
tự do — hợp lý khi chạy local. Nhớ dùng HTTPS (link onrender.com đã có sẵn HTTPS) để mật
khẩu không bị lộ trên đường truyền.

**Lưu ý bản miễn phí:** service ngủ sau 15 phút không dùng, lần mở lại đầu tiên chậm
(~30 giây khởi động). Xử lý vài trăm domain lần đầu mất vài phút vì phải tải từng trang.

## Cấu trúc lọc

| Cấp | Ý nghĩa |
|-----|---------|
| 🚨 Cấp 1 | Loại ngay — malware, phishing, cờ bạc, người lớn, lậu, crypto scam |
| ⚠️ Cấp 2 | Chất lượng thấp — domain mới, nội dung mỏng, nhồi quảng cáo, kiếm tiền |
| 🎮 Cấp 3 | Thường không hợp ads — game/giải trí |
| 🎯 Cấp 4 | Tùy khách — việc làm, giáo dục, tài chính, BĐS (mặc định tắt) |
| 🛡️ Giảm nhầm | Domain lâu năm, TLD .gov/.edu |

Ô màu xám gạch ngang là **chưa làm được** (cần đọc hiểu nội dung — sẽ mở khi gắn tầng LLM),
không phải đang tắt.

## Giới hạn quan trọng

- Chỉ đọc **trang chủ**, không đọc từng bài viết bên trong.
- Trang chặn bot / đã chết → ghi *"Không tải được trang"*, **không phải là sạch**.
- **Tuổi domain cao ≠ trang tốt.** Tuổi chỉ dùng để giảm mức chặn.
- Bộ nhớ tạm `domain_cache.json` **không tự hết hạn** — muốn quét lại phải xoá.
- Ô **Malware/Threat đang khoá**: nguồn urlscan không trả kết quả quét mã độc.
- Tool **thu hẹp việc xem tay, không thay thế việc xem tay**.
