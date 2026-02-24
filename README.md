# Copilot API Dashboard

Biến GitHub Copilot thành server API tương thích OpenAI/Anthropic, kèm Dashboard quản lý token và API key.

## ✨ Tính năng

- **OpenAI Compatible API** — Hỗ trợ `/v1/chat/completions`, `/v1/models`, `/v1/embeddings`
- **Anthropic Compatible** — Hỗ trợ `/v1/messages`
- **Dashboard quản lý** — Giao diện web quản lý GitHub token, API key, theo dõi usage
- **Multi-token** — Quản lý nhiều GitHub token, chuyển đổi token active
- **API Key Authentication** — Bảo mật endpoint bằng API key
- **Docker** — Deploy nhanh với Docker Compose

## 📋 Yêu cầu

- **VPS/Server** với Docker và Docker Compose đã cài đặt
- **GitHub Account** có quyền truy cập Copilot
- **GitHub Token** — Lấy bằng lệnh:
  ```sh
  npx copilot-api@latest auth --show-token
  ```

## 🚀 Cài đặt trên Server

### 1. Clone dự án

```sh
git clone https://github.com/tocongtruong/copilot_api_dashboard.git
cd copilot_api_dashboard
```

### 2. Tạo file `.env`

```sh
cp .env .env.backup   # backup nếu cần
nano .env
```

Chỉnh sửa các giá trị trong file `.env`:

```env
# GitHub Token (bắt buộc)
GH_TOKEN=your_github_token_here

# Ports
COPILOT_API_PORT=4141
DASHBOARD_PORT=3000

# Security - ĐỔI CÁC GIÁ TRỊ NÀY
INTERNAL_SECRET=your-random-secret-here
JWT_SECRET=your-jwt-secret-here
ADMIN_PASSWORD=your-admin-password

# Bật xác thực API key (khuyến nghị: true)
ENABLE_API_AUTH=true
```

> ⚠️ **Quan trọng:** Hãy thay đổi `INTERNAL_SECRET`, `JWT_SECRET` và `ADMIN_PASSWORD` thành các giá trị bảo mật riêng.

### 3. Khởi chạy với Docker Compose

```sh
docker compose up -d
```

Kiểm tra trạng thái:

```sh
docker compose ps
docker compose logs -f
```

### 4. Truy cập

| Service       | URL                          |
| ------------- | ---------------------------- |
| Copilot API   | `http://<server-ip>:4141`    |
| Dashboard     | `http://<server-ip>:3000`    |

- Đăng nhập Dashboard bằng mật khẩu admin đã cấu hình trong `.env`

## 🔄 Cập nhật

Khi có phiên bản mới:

```sh
cd copilot_api_dashboard
git pull origin master
docker compose down
docker compose up -d --build
```

## 📡 API Endpoints

### OpenAI Compatible

| Method | Endpoint               | Mô tả                    |
| ------ | ---------------------- | ------------------------- |
| POST   | `/v1/chat/completions` | Chat completions          |
| GET    | `/v1/models`           | Danh sách models          |
| POST   | `/v1/embeddings`       | Text embeddings           |

### Anthropic Compatible

| Method | Endpoint        | Mô tả               |
| ------ | --------------- | -------------------- |
| POST   | `/v1/messages`  | Anthropic Messages   |

### Khác

| Method | Endpoint   | Mô tả              |
| ------ | ---------- | ------------------- |
| GET    | `/health`  | Health check        |
| GET    | `/models`  | Danh sách models    |
| GET    | `/usage`   | Thống kê sử dụng   |
| GET    | `/token`   | Thông tin token     |

### Ví dụ gọi API

```sh
curl http://<server-ip>:4141/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-api-key>" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## 🐳 Docker Services

| Container          | Mô tả                                   | Port |
| ------------------ | ---------------------------------------- | ---- |
| `copilot-api`      | API proxy server (Bun + Hono)            | 4141 |
| `copilot-dashboard`| Dashboard quản lý (Node.js + Express)    | 3000 |

### Volumes

- `copilot-data` — Dữ liệu Copilot API
- `dashboard-data` — Database SQLite của Dashboard

## 🛠️ Lệnh thường dùng

```sh
# Xem logs
docker compose logs -f

# Restart services
docker compose restart

# Dừng services
docker compose down

# Rebuild và khởi động lại
docker compose up -d --build

# Xem trạng thái
docker compose ps
```

## 📁 Cấu trúc dự án

```
copilot_api_dashboard/
├── docker-compose.yml      # Docker Compose config
├── Dockerfile              # Dockerfile cho Copilot API
├── entrypoint.sh           # Entrypoint script
├── package.json            # Dependencies
├── .env                    # Biến môi trường
├── src/                    # Source code Copilot API
│   ├── main.ts
│   ├── server.ts
│   ├── lib/                # Thư viện core
│   ├── routes/             # API routes
│   └── services/           # Services
└── dashboard/              # Dashboard web UI
    ├── Dockerfile
    ├── server.js
    └── public/             # Frontend files
```

## 📄 License

MIT

---

> Dự án dựa trên [copilot-api](https://github.com/ericc-ch/copilot-api) của Erick Christian, được mở rộng thêm Dashboard quản lý.
