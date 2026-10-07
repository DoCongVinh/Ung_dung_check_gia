# Vinh Ứng dụng tra cứu

Micro-SaaS tạo báo giá/hóa đơn cho doanh nghiệp nhỏ, xây dựng bằng Python 3, FastAPI, SQLAlchemy, SQLite và giao diện Jinja2 responsive.

Ứng dụng Desktop tùy chọn chạy tại `desktop_app/app.py`, đăng nhập qua API FastAPI và đồng bộ khách hàng, sản phẩm, báo giá/hóa đơn.

## Tính năng

- Đăng ký với username duy nhất và chỉ chấp nhận Gmail (`@gmail.com`, `@gmail.com.vn`); đăng nhập bằng email hoặc username, cookie JWT `HttpOnly`, phân quyền User/Admin và CSRF cho biểu mẫu.
- Thông báo đăng ký mới trong dashboard Admin; database cũ tự thêm cột username và backfill tên đăng nhập duy nhất khi khởi động.
- Admin quản lý gói dịch vụ, ngân hàng/QR, user, trial và thời hạn gói trực tiếp từ dashboard; tài khoản `admin@gmail.com` đang có sẽ được nâng vai trò khi ứng dụng khởi động.
- API Desktop có Bearer token cho đăng nhập, hồ sơ/gói, khách hàng, sản phẩm và báo giá/hóa đơn.
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

Lần khởi động đầu tiên sẽ tạo các gói dịch vụ. Email admin mặc định là `admin@gmail.com`; để tạo tài khoản admin, đặt `ADMIN_PASSWORD` qua biến môi trường trước khi chạy (mật khẩu phải có ít nhất 10 ký tự, một chữ hoa, một số và một ký tự đặc biệt). Có thể đặt `ADMIN_EMAIL` để đổi email. Không nhúng mật khẩu vào mã nguồn. Tài khoản admin hiện có sẽ không bị ghi đè khi khởi động lại. Đặt `COOKIE_SECURE=true` khi chạy sau HTTPS; đặt `SECRET_KEY` riêng, ngẫu nhiên và ổn định giữa các lần khởi động.

Nếu database đã có `admin@gmail.com` với quyền User, ứng dụng sẽ tự cấp lại vai trò Admin ở lần khởi động tiếp theo. Tài khoản vẫn giữ nguyên mật khẩu đang dùng; không dùng `ADMIN_PASSWORD` để ghi đè lên mật khẩu một tài khoản đã tồn tại.

Đăng ký người dùng chỉ chấp nhận Gmail (`@gmail.com`/`@gmail.com.vn`), username duy nhất và mật khẩu mạnh; hồ sơ có phương thức khôi phục qua mật khẩu cấp 2/câu trả lời bí mật hoặc yêu cầu Admin reset. Admin có thể xem/quản lý trạng thái, trial, hạn gói, số dư và yêu cầu reset tại **Người dùng**.

Khi nâng cấp database cũ, ứng dụng tự thêm cột `username`, tạo username duy nhất từ phần trước `@` của email cho tài khoản hiện có (thêm hậu tố số nếu bị trùng), rồi tạo unique index. Hãy sao lưu `app.db` trước khi nâng cấp production. Mật khẩu vẫn giữ nguyên hash hiện có; tài khoản cũ có thể đăng nhập bằng email hoặc username mới được sinh.

Sau khi đăng nhập bằng admin:

1. Vào **Tổng quan** để quản lý gói, giá, giới hạn và thêm tài khoản ngân hàng/ví (có thể lưu URL QR HTTPS).
2. Vào **Người dùng** để tạo/sửa/xóa user, cấp/gia hạn/tắt trial, điều chỉnh số dư hoặc khóa tài khoản.
3. Người dùng chọn gói, chuyển đúng số tiền và nội dung; Admin đối chiếu rồi duyệt/từ chối yêu cầu.
4. Người dùng dùng các demo tại **Sản phẩm & dịch vụ** hoặc mở workspace đã kích hoạt để tạo khách hàng, sản phẩm, báo giá và hóa đơn.

### Mở Desktop companion trên Windows

Sau khi cài Python và dependencies của ứng dụng Web, có thể mở Desktop companion bằng cách nhấp đúp `desktop_app\run_desktop.bat`. Launcher tự ưu tiên Python trong `.venv`, sau đó thử Python Launcher (`pyw`) hoặc `pythonw.exe`; không cần gõ lệnh.

Backend cần đang chạy tại địa chỉ đã nhập trên màn hình đăng nhập. Nếu dùng mặc định `http://127.0.0.1:8000`, hãy khởi động ứng dụng Web trước; nếu backend được triển khai ở domain khác, nhập domain đó vào trường **Địa chỉ Web**. Có thể tạo shortcut ngoài Desktop bằng cách nhấp phải `run_desktop.bat` → **Show more options** → **Send to** → **Desktop (create shortcut)**.

Hoặc chạy thủ công từ PowerShell:

```powershell
py -3 desktop_app\app.py
```

Đăng nhập bằng tài khoản web. Desktop API cảnh báo khi gói còn dưới 5 ngày hoặc đã hết hạn. Các luồng nghiệp vụ cốt lõi có sẵn trong ứng dụng desktop; nút **Mở toàn bộ ứng dụng Web** mở giao diện Web đầy đủ. API sử dụng HTTPS khi triển khai công khai.

Thông tin bank/ví là dữ liệu do admin nhập. Ứng dụng không kết nối API ngân hàng, không tự xác minh tiền đến; admin cần đối chiếu giao dịch thủ công trước khi duyệt.

## Cấu trúc

```text
main.py                 FastAPI routes, auth, thanh toán, tài liệu, API Desktop và PDF
models.py               Models SQLAlchemy (Proposal/Invoice là các subtype của Document)
database.py             Kết nối và session database
templates/              Giao diện Jinja2
static/                 CSS responsive và JavaScript
desktop_app/            Desktop Tkinter companion và hướng dẫn dependencies
requirements.txt        Dependencies
```

## Đẩy mã nguồn lên GitHub

Từ thư mục repository:

```powershell
git status
git add .
git commit -m "Upgrade Vinh lookup app administration and desktop client"
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
