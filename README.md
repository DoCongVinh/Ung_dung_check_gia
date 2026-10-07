# Paperwise — Auto Proposal & Invoice Generator

Micro-SaaS tạo báo giá/hóa đơn cho doanh nghiệp nhỏ, xây dựng bằng Python 3, FastAPI, SQLAlchemy, SQLite và giao diện Jinja2 responsive.

## Tính năng

- Đăng ký/đăng nhập, cookie phiên JWT `HttpOnly`, phân quyền User/Admin và bảo vệ CSRF cho biểu mẫu.
- Hồ sơ doanh nghiệp và CRM khách hàng; danh mục sản phẩm/dịch vụ, giá và đơn vị tính.
- Tạo báo giá/hóa đơn, tính số lượng, chiết khấu, VAT ở backend; theo dõi trạng thái bản nháp → đã gửi → đã chấp nhận/đã thanh toán.
- Tải tài liệu PDF. Trên Windows dùng font Arial/Calibri có sẵn; nếu triển khai Linux, cấu hình `PDF_FONT_PATH` trỏ tới font TTF hỗ trợ tiếng Việt.
- Gói Cơ bản, Pro, Enterprise; admin có thể thêm tài khoản Vietcombank, Techcombank, MBBank, BIDV, Agribank, VietinBank, ACB, TPBank, MoMo hoặc ZaloPay.
- Mã/nội dung chuyển khoản riêng cho từng yêu cầu. Admin duyệt hoặc từ chối trong vòng 2 giờ từ lúc người dùng xác nhận đã chuyển khoản; chỉ khi được duyệt thì gói mới được kích hoạt.
- SQLite được tạo tự động trong `app.db`; có thể chuyển sang database khác qua `DATABASE_URL` (SQLAlchemy).

## Chạy trên Windows

Yêu cầu Python 3.10 trở lên.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:SECRET_KEY = "thay-bang-chuoi-ngau-nhien-dai-va-bao-mat"
$env:ADMIN_EMAIL = "admin@example.com"
$env:ADMIN_PASSWORD = "ThayBangMatKhauAdminManh"
$env:COOKIE_SECURE = "false"
uvicorn main:app --reload
```

Mở <http://127.0.0.1:8000>. Endpoint kiểm tra hoạt động: <http://127.0.0.1:8000/health>.

Lần khởi động đầu tiên sẽ tạo các gói dịch vụ và tài khoản admin (nếu đặt `ADMIN_EMAIL`/`ADMIN_PASSWORD`). Tài khoản admin hiện có sẽ không bị ghi đè khi khởi động lại. Không dùng mật khẩu mẫu trong production. Đặt `COOKIE_SECURE=true` khi chạy sau HTTPS; đặt `SECRET_KEY` riêng, ngẫu nhiên và ổn định giữa các lần khởi động.

Sau khi đăng nhập bằng admin:

1. Mở **Tổng quan** và thêm tài khoản ngân hàng/ví nhận thanh toán.
2. Người dùng đăng ký, chọn gói và chuyển đúng số tiền với nội dung hiển thị.
3. Người dùng bấm **Tôi đã chuyển khoản** để đưa yêu cầu vào hàng chờ duyệt. Admin đối chiếu giao dịch, tên doanh nghiệp và số tiền rồi duyệt/từ chối.
4. Sau khi được duyệt, người dùng có thể tạo khách hàng, sản phẩm, báo giá và hóa đơn.

Thông tin bank/ví là dữ liệu do admin nhập. Ứng dụng không kết nối API ngân hàng, không tự xác minh tiền đến; admin cần đối chiếu giao dịch thủ công trước khi duyệt.

## Cấu trúc

```text
main.py                 FastAPI routes, auth, thanh toán, tài liệu và xuất PDF
models.py               Models SQLAlchemy (Proposal/Invoice là các subtype của Document)
database.py             Kết nối và session database
templates/              Giao diện Jinja2
static/                 CSS responsive và JavaScript
requirements.txt        Dependencies
```

## Đẩy mã nguồn lên GitHub

Từ thư mục repository:

```powershell
git status
git add .
git commit -m "Build Paperwise proposal and invoice SaaS"
git push origin main
```

Nếu nhánh hiện tại chưa theo dõi nhánh remote:

```powershell
git push -u origin main
```

Không commit `.env`, khóa bí mật, database production hoặc thông tin tài khoản ngân hàng thật. `.gitignore` đã bỏ qua database SQLite và `.env`.

## Lưu ý triển khai

- Bản khởi đầu dùng SQLite và một tiến trình ứng dụng. Với môi trường nhiều worker/người dùng, dùng PostgreSQL, HTTPS, secret manager, sao lưu định kỳ và giới hạn đăng nhập tại reverse proxy.
- Thời hạn dùng gói được tính theo số ngày cấu hình trong `PACKAGE_SEEDS`. Hạn 2 giờ của thanh toán bắt đầu khi người dùng bấm xác nhận đã chuyển.
- Giới hạn số khách hàng/tài liệu của từng gói được lưu để hiển thị và quản trị; bản hiện tại chưa chặn tạo mới theo các hạn mức này.
