# Triển khai Klock lên subdomain riêng (server có sẵn, đang chạy Nginx)

Thay `klock.tenban.com` bằng subdomain thật của bạn, và `/opt/klock` bằng nơi bạn đặt code trên server.

## 1. DNS
Ở nơi quản lý DNS của domain (registrar, hoặc Vercel nếu bạn add domain vào đó), thêm:

```
Type: A
Name: klock          (hoặc subdomain bạn muốn)
Value: <IP công khai của server bạn>
```

Domain gốc và các bản ghi khác giữ nguyên, không bị ảnh hưởng.

## 2. Đưa code + build trên server

```bash
git clone <repo-cua-ban> /opt/klock
cd /opt/klock/web
cargo build --release
```

## 3. Chạy như systemd service (tự khởi động lại, chạy nền vĩnh viễn)

Tạo file `/etc/systemd/system/klock-web.service`:

```ini
[Unit]
Description=Klock web
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/klock/web
Environment=KLOCK_ADDR=127.0.0.1:8787
Environment=KLOCK_DB=/opt/klock/web/klock_web_data.json
Environment=KLOCK_STATIC=/opt/klock/web/static
ExecStart=/opt/klock/web/target/release/klock-web
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now klock-web
sudo systemctl status klock-web   # kiểm tra chạy OK
```

Lưu ý: app chỉ bind `127.0.0.1:8787` (không lộ ra ngoài trực tiếp) — Nginx sẽ là cổng vào duy nhất.

## 4. Thêm site mới vào Nginx (không đụng site hiện tại)

Tạo file `/etc/nginx/sites-available/klock`:

```nginx
server {
    listen 80;
    server_name klock.tenban.com;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/klock /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

`sudo nginx -t` báo lỗi thì sửa trước khi reload — site hiện tại của bạn không bị ảnh hưởng vì đây là server block riêng, khớp theo `server_name`.

## 5. Bật HTTPS (bắt buộc — xem lý do trong BAO_CAO_BAO_MAT.md)

```bash
sudo apt install certbot python3-certbot-nginx   # nếu chưa có
sudo certbot --nginx -d klock.tenban.com
```

Certbot tự sửa file Nginx ở bước 4 để thêm HTTPS + redirect HTTP→HTTPS, và tự gia hạn chứng chỉ.

## 6. Kiểm tra

Mở `https://klock.tenban.com` — phải thấy giao diện Klock, mã hóa/giải mã thử một lượt để chắc chắn.

---

**Đã sửa sẵn trong code**: rate-limit giờ đọc đúng IP thật của người dùng qua header `X-Forwarded-For` mà Nginx gắn vào (bước 4 ở trên), thay vì tính nhầm tất cả người dùng thành IP của Nginx (127.0.0.1).
