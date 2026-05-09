# ⚔️🛡️ Brute Force Login — Attack & Defense System

> Hệ thống phát hiện và chặn tấn công Brute Force Login với Attack Simulator tích hợp.

## 📝 Mô tả dự án

Đồ án môn **Lập trình ứng dụng với Python 3** — Xây dựng hệ thống bảo mật web có khả năng:
- **Tấn công (Red Team):** Mô phỏng các kiểu tấn công brute force, dictionary attack
- **Phòng thủ (Blue Team):** Phát hiện, chặn tự động và giám sát qua SOC Dashboard

## 👥 Thành viên nhóm

| STT | Họ tên | MSSV | Vai trò | Nhiệm vụ chính |
|-----|--------|------|---------|----------------|
| 1 | Nguyễn Văn Phú | | Leader | Backend, Detection Engine, Blocking Engine, API |
| 2 | Lê Quang Tùng | | Member | Giao diện HTML/CSS, Dashboard UI |
| 3 | Nguyễn Hồng Phong | | Member | Dữ liệu mẫu, Tài liệu, Kiểm thử |

## ✨ Chức năng chính

### 🔐 Hệ thống xác thực
- Đăng ký / Đăng nhập với mã hóa mật khẩu (Bcrypt)
- Đăng nhập Social OAuth: Google / GitHub / Microsoft
- Quản lý phiên đăng nhập (Session)
- Phân quyền Admin / User
- CAPTCHA sau nhiều lần đăng nhập thất bại

### 🔍 Phát hiện tấn công (Detection Engine)
- Theo dõi đăng nhập thất bại theo IP và Username
- Phát hiện Brute Force và Credential Stuffing
- Rate Limiting — giới hạn số request/phút
- Cảnh báo realtime khi phát hiện tấn công

### 🚫 Chặn tự động (Blocking Engine)
- Khóa tài khoản tạm thời sau N lần thất bại
- Chặn IP tạm thời / vĩnh viễn
- Whitelist / Blacklist IP
- Admin unlock thủ công qua Dashboard

### 📊 Dashboard giám sát (SOC Dashboard)
- Tổng quan: số lần login, thất bại, IP bị chặn
- Biểu đồ hoạt động đăng nhập theo thời gian
- Bảng log chi tiết có tìm kiếm, lọc, phân trang
- Quản lý IP bị chặn và tài khoản bị khóa
- Cấu hình ngưỡng bảo mật

### ⚔️ Mô phỏng tấn công (Attack Simulator)
- Brute Force đơn giản
- Dictionary Attack (từ file wordlist)
- Credential Stuffing
- Báo cáo kết quả tấn công

## 🛠️ Công nghệ sử dụng

| Thành phần | Công nghệ |
|------------|-----------|
| Ngôn ngữ | Python 3.10+ |
| Web Framework | Flask 3.x |
| Database | SQLite |
| ORM | SQLAlchemy |
| Auth | Flask-Login, Flask-Bcrypt |
| Frontend | Jinja2, Chart.js, DataTables.js |
| Testing | pytest |

## 🚀 Hướng dẫn cài đặt

```bash
# 1. Clone dự án
git clone https://github.com/phunv123/brute-force-login-defense-python.git
cd brute-force-login-defense-python

# 2. Tạo môi trường ảo
python3 -m venv venv
source venv/bin/activate

# 3. Cài đặt thư viện
pip install -r requirements.txt

# 4. Cấu hình môi trường
cp .env.example .env

# 5. Chạy ứng dụng
python run.py
```

Mở trình duyệt: `http://localhost:5000`

## 🔑 Cấu hình Social Login (OAuth)

Hệ thống hỗ trợ OAuth thật cho Google / GitHub / Microsoft.

### 1. Khai báo biến môi trường trong `.env`
```env
OAUTH_GOOGLE_CLIENT_ID=...
OAUTH_GOOGLE_CLIENT_SECRET=...

OAUTH_GITHUB_CLIENT_ID=...
OAUTH_GITHUB_CLIENT_SECRET=...

OAUTH_MICROSOFT_CLIENT_ID=...
OAUTH_MICROSOFT_CLIENT_SECRET=...
OAUTH_MICROSOFT_TENANT=common
```

### 2. Callback URL cần đăng ký trên provider
- Google: `http://127.0.0.1:5000/oauth/google/callback`
- GitHub: `http://127.0.0.1:5000/oauth/github/callback`
- Microsoft: `http://127.0.0.1:5000/oauth/microsoft/callback`

Sau khi cấu hình, các nút social trên trang Login/Register sẽ đăng nhập thật qua OAuth.

## 📁 Cấu trúc dự án

```
brute-force-login-defense-python/
├── app/                    # Code chính
│   ├── models/             # Database models
│   ├── services/           # Business logic
│   ├── routes/             # API & page routes
│   ├── templates/          # HTML templates
│   └── static/             # CSS, JS, images
├── simulator/              # Công cụ mô phỏng tấn công
│   └── wordlists/          # Danh sách mật khẩu
├── tests/                  # Unit tests
├── docs/                   # Tài liệu
├── scripts/                # Scripts tiện ích
├── requirements.txt        # Danh sách thư viện Python
├── .env.example            # Template cấu hình
└── .gitignore              # Danh sách file bỏ qua
```

## 📄 Giấy phép

MIT License
