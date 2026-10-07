"""Auto Proposal & Invoice Generator - FastAPI application."""

import os
import re
import secrets
import warnings
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from xml.sax.saxutils import escape

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from models import (
    BankAccount,
    Customer,
    Document,
    DocumentItem,
    Invoice,
    Notification,
    Package,
    PasswordResetRequest,
    PaymentRequest,
    Product,
    Proposal,
    User,
    utcnow,
)
from database import SessionLocal, init_db


ROOT = Path(__file__).resolve().parent
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(48)
if not os.getenv("SECRET_KEY"):
    warnings.warn(
        "SECRET_KEY is not set; sessions will be invalidated when the app restarts. "
        "Set a stable random value before deployment.",
        stacklevel=1,
    )
ALGORITHM = "HS256"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "720"))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
templates = Jinja2Templates(directory=str(ROOT / "templates"))

app = FastAPI(title="Vinh Ứng dụng tra cứu", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")

VN_BANKS = [
    "Vietcombank",
    "Techcombank",
    "MBBank",
    "BIDV",
    "Agribank",
    "VietinBank",
    "ACB",
    "TPBank",
    "MoMo",
    "ZaloPay",
]
PACKAGE_SEEDS = [
    {
        "name": "Cơ bản",
        "description": "Dành cho cá nhân và doanh nghiệp mới bắt đầu.",
        "price": Decimal("199000"),
        "customer_limit": 100,
        "document_limit": 100,
    },
    {
        "name": "Pro",
        "description": "Tự động hóa quy trình báo giá và hóa đơn hằng ngày.",
        "price": Decimal("499000"),
        "customer_limit": 1000,
        "document_limit": 1000,
    },
    {
        "name": "Enterprise",
        "description": "Không gian làm việc mở rộng cho đội ngũ đang phát triển.",
        "price": Decimal("1499000"),
        "customer_limit": 10000,
        "document_limit": 10000,
    },
]
MAX_AMOUNT = Decimal("9999999999.99")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
GMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:gmail\.com|gmail\.com\.vn)$",
    re.IGNORECASE,
)
GMAIL_ERROR = (
    "Hệ thống chỉ chấp nhận địa chỉ Email Gmail "
    "(@gmail.com hoặc @gmail.com.vn)."
)
PASSWORD_PATTERN = re.compile(r"^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$")
PROFILE_FIELDS = {
    "Số điện thoại": lambda user: user.phone,
    "Số tài khoản ngân hàng": lambda user: user.bank_account_number,
    "Mật khẩu cấp 2": lambda user: user.secondary_password_hash,
    "Câu trả lời bảo mật": lambda user: user.security_answer_hash,
}
MAX_BALANCE = Decimal("999999999999.99")


class DesktopLoginPayload(BaseModel):
    identifier: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class DesktopCustomerPayload(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    company: str = Field(default="", max_length=200)
    email: str = Field(default="", max_length=255)
    phone: str = Field(default="", max_length=50)
    address: str = Field(default="", max_length=2000)
    tax_code: str = Field(default="", max_length=50)


class DesktopProductPayload(BaseModel):
    name: str = Field(min_length=1, max_length=180)
    description: str = Field(default="", max_length=2000)
    unit: str = Field(default="lần", max_length=40)
    unit_price: Decimal = Field(gt=0, le=MAX_AMOUNT)


class DesktopDocumentItemPayload(BaseModel):
    product_id: int
    quantity: Decimal = Field(gt=0, le=Decimal("1000000"))


class DesktopDocumentPayload(BaseModel):
    kind: str
    customer_id: int
    title: str = Field(min_length=1, max_length=200)
    items: list[DesktopDocumentItemPayload] = Field(min_length=1, max_length=100)
    discount_percent: Decimal = Field(default=Decimal("0"), ge=0, le=100)
    tax_percent: Decimal = Field(default=Decimal("0"), ge=0, le=100)
    notes: str = Field(default="", max_length=4000)


class DesktopDocumentStatusPayload(BaseModel):
    status: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.middleware("http")
async def security_and_csrf_cookie(request: Request, call_next):
    csrf = request.cookies.get("csrf_token") or secrets.token_urlsafe(32)
    request.state.csrf_token = csrf
    response = await call_next(request)
    if not request.cookies.get("csrf_token"):
        response.set_cookie(
            "csrf_token",
            csrf,
            httponly=False,
            secure=COOKIE_SECURE,
            samesite="lax",
            max_age=60 * 60 * 24 * 30,
        )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def csrf_protected(
    request: Request,
    csrf_token: str = Form(...),
) -> None:
    cookie = request.cookies.get("csrf_token", "")
    if not cookie or not secrets.compare_digest(cookie, csrf_token):
        raise HTTPException(status_code=403, detail="Phiên biểu mẫu không hợp lệ. Hãy tải lại trang.")


def render(request: Request, template: str, **context):
    context["csrf_token"] = getattr(request.state, "csrf_token", "")
    context.setdefault("missing_profile_fields", missing_profile_fields(context.get("user")))
    return templates.TemplateResponse(
        request=request,
        name=template,
        context=context,
    )


def missing_profile_fields(user: User | None) -> list[str]:
    if user is None or user.role == "admin":
        return []
    return [label for label, getter in PROFILE_FIELDS.items() if not getter(user)]


def password_policy_error(password: str) -> str | None:
    if len(password) < 10:
        return "Mật khẩu cần có ít nhất 10 ký tự."
    if len(password.encode("utf-8")) > 72:
        return "Mật khẩu không được vượt quá 72 byte."
    if not PASSWORD_PATTERN.search(password):
        return "Mật khẩu phải có ít nhất 1 chữ in hoa, 1 chữ số và 1 ký tự đặc biệt."
    return None


def normalize_security_answer(answer: str) -> str:
    return " ".join(answer.split()).casefold()


def hash_security_answer(answer: str) -> str:
    return pwd_context.hash(normalize_security_answer(answer))


def verify_security_answer(answer: str, stored_hash: str | None) -> bool:
    return bool(
        stored_hash
        and pwd_context.verify(normalize_security_answer(answer), stored_hash)
    )


def create_access_token(user: User) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode(
        {"sub": str(user.id), "role": user.role, "exp": expires},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub", ""))
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=303, headers={"Location": "/login"}) from None
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.account_status != "active":
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập khu vực quản trị.")
    return user


def subscription_is_active(user: User) -> bool:
    if user.role == "admin":
        return True
    trial_expires = user.trial_expires_at
    if trial_expires is not None:
        if trial_expires.tzinfo is None:
            trial_expires = trial_expires.replace(tzinfo=timezone.utc)
        if trial_expires > datetime.now(timezone.utc):
            return True
    expires = user.subscription_expires_at
    if not user.package_id or expires is None:
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > datetime.now(timezone.utc)


def require_subscription(user: User = Depends(get_current_user)) -> User:
    if not subscription_is_active(user):
        raise HTTPException(status_code=303, headers={"Location": "/pricing"})
    return user


def money(value: Decimal | int | float | None) -> str:
    amount = Decimal(str(value or 0)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return f"{amount:,.0f} ₫".replace(",", ".")


templates.env.filters["money"] = money
templates.env.globals["now"] = datetime.now


def safe_next_status(current: str, new_status: str) -> bool:
    transitions = {
        "draft": {"sent"},
        "sent": {"accepted", "paid"},
        "accepted": {"paid"},
    }
    return new_status in transitions.get(current, set())


def get_owned_document(db: Session, document_id: int, user_id: int) -> Document:
    document = db.scalar(
        select(Document)
        .options(selectinload(Document.items), selectinload(Document.customer))
        .where(Document.id == document_id, Document.owner_id == user_id)
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài liệu.")
    return document


@app.on_event("startup")
def initialize_database() -> None:
    init_db()
    with SessionLocal() as db:
        for seed in PACKAGE_SEEDS:
            if db.scalar(select(Package.id).where(Package.name == seed["name"])) is None:
                db.add(Package(**seed))
        db.commit()
        admin_email = os.getenv("ADMIN_EMAIL", "admin@gmail.com").strip().lower()
        admin_password = os.getenv("ADMIN_PASSWORD", "")
        admin = db.scalar(select(User).where(func.lower(User.email) == admin_email))
        if admin_password:
            if password_policy_error(admin_password):
                raise RuntimeError(
                    "ADMIN_PASSWORD must contain at least 10 characters, "
                    "one uppercase letter, one digit, and one special character."
                )
            if admin is None:
                base_username = re.sub(
                    r"[^a-z0-9_.-]", "", admin_email.split("@", 1)[0].lower()
                )[:24]
                if len(base_username) < 3:
                    base_username = "admin"
                admin_username = base_username
                suffix = 1
                while db.scalar(
                    select(User.id).where(func.lower(User.username) == admin_username)
                ):
                    tail = str(suffix)
                    admin_username = f"{base_username[:30 - len(tail)]}{tail}"
                    suffix += 1
                db.add(
                    User(
                        email=admin_email,
                        username=admin_username,
                        password_hash=pwd_context.hash(admin_password),
                        full_name=os.getenv("ADMIN_NAME", "Quản trị viên"),
                        role="admin",
                        account_status="active",
                    )
                )
                db.commit()
        if admin is not None and (
            admin.role != "admin"
            or not admin.is_active
            or admin.account_status != "active"
        ):
            admin.role = "admin"
            admin.account_status = "active"
            admin.is_active = True
            db.commit()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render(request, "landing.html")


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return render(request, "register.html", error=None)


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    db: Session = Depends(get_db),
    _csrf: None = Depends(csrf_protected),
    username: str = Form(..., max_length=30),
    full_name: str = Form(..., max_length=160),
    company_name: str = Form("", max_length=200),
    email: str = Form(..., max_length=255),
    password: str = Form(..., max_length=128),
    confirm_password: str = Form(..., max_length=128),
):
    username = username.strip().lower()
    normalized_email = email.strip().lower()
    full_name = full_name.strip()
    form_data = {
        "username": username,
        "full_name": full_name,
        "company_name": company_name.strip(),
        "email": normalized_email,
    }
    if not GMAIL_PATTERN.fullmatch(normalized_email) or ".." in normalized_email.split("@", 1)[0]:
        return render(
            request,
            "register.html",
            error=GMAIL_ERROR,
            form_data=form_data,
        )
    local_part = normalized_email.split("@", 1)[0]
    if local_part.startswith(".") or local_part.endswith("."):
        return render(
            request,
            "register.html",
            error="Vui lòng nhập địa chỉ Email hợp lệ.",
            form_data=form_data,
        )
    if not USERNAME_PATTERN.fullmatch(username):
        return render(
            request,
            "register.html",
            error="Tên đăng nhập phải có 3–30 ký tự, chỉ gồm chữ cái không dấu, số, dấu chấm, gạch dưới hoặc gạch ngang.",
            form_data=form_data,
        )
    if len(full_name) < 2:
        return render(
            request,
            "register.html",
            error="Họ và tên cần có ít nhất 2 ký tự.",
            form_data=form_data,
        )
    admin_email = os.getenv("ADMIN_EMAIL", "admin@gmail.com").strip().lower()
    if normalized_email == admin_email:
        return render(
            request,
            "register.html",
            error="Địa chỉ Email này được dành riêng cho quản trị viên.",
            form_data=form_data,
        )
    if error := password_policy_error(password):
        return render(
            request,
            "register.html",
            error=error,
            form_data=form_data,
        )
    if password != confirm_password:
        return render(
            request,
            "register.html",
            error="Mật khẩu xác nhận không khớp.",
            form_data=form_data,
        )
    if db.scalar(select(User.id).where(func.lower(User.email) == normalized_email)):
        return render(
            request,
            "register.html",
            error="Email này đã được đăng ký.",
            form_data=form_data,
        )
    if db.scalar(select(User.id).where(func.lower(User.username) == username)):
        return render(
            request,
            "register.html",
            error="Tên đăng nhập này đã được sử dụng.",
            form_data=form_data,
        )
    user = User(
        username=username,
        email=normalized_email,
        full_name=full_name,
        company_name=company_name.strip(),
        password_hash=pwd_context.hash(password),
    )
    db.add(user)
    try:
        db.flush()
        db.add(
            Notification(
                user_id=user.id,
                message=f"Người dùng mới {user.username} ({user.email}) vừa đăng ký tài khoản thành công.",
            )
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        if db.scalar(select(User.id).where(func.lower(User.email) == normalized_email)):
            error = "Email này đã được đăng ký."
        elif db.scalar(select(User.id).where(func.lower(User.username) == username)):
            error = "Tên đăng nhập này đã được sử dụng."
        else:
            error = "Không thể hoàn tất đăng ký do dữ liệu bị trùng. Hãy thử lại."
        return render(request, "register.html", error=error, form_data=form_data)
    return RedirectResponse("/login?registered=1", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, registered: bool = False):
    return render(request, "login.html", error=None, registered=registered)


@app.post("/login")
def login(
    request: Request,
    db: Session = Depends(get_db),
    _csrf: None = Depends(csrf_protected),
    identifier: str = Form(...),
    password: str = Form(...),
):
    normalized_identifier = identifier.strip().lower()
    user = db.scalar(
        select(User).where(
            or_(
                func.lower(User.email) == normalized_identifier,
                func.lower(User.username) == normalized_identifier,
            )
        )
    )
    if (
        user is None
        or not user.is_active
        or user.account_status != "active"
        or len(password.encode("utf-8")) > 72
        or not pwd_context.verify(password, user.password_hash)
    ):
        return render(request, "login.html", error="Email/Tên đăng nhập hoặc mật khẩu không chính xác.")
    response = RedirectResponse("/admin" if user.role == "admin" else "/app", status_code=303)
    response.set_cookie(
        "access_token",
        create_access_token(user),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=ACCESS_TOKEN_MINUTES * 60,
    )
    return response


@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return render(request, "forgot_password.html", error=None, success=None)


@app.post("/forgot-password/self-reset", response_class=HTMLResponse)
def self_reset_password(
    request: Request,
    identifier: str = Form(..., max_length=255),
    security_answer: str = Form(..., min_length=1, max_length=255),
    secondary_password: str = Form(..., max_length=128),
    new_password: str = Form(..., max_length=128),
    confirm_password: str = Form(..., max_length=128),
    db: Session = Depends(get_db),
    _csrf: None = Depends(csrf_protected),
):
    normalized = identifier.strip().lower()
    user = db.scalar(
        select(User).where(
            or_(func.lower(User.email) == normalized, func.lower(User.username) == normalized)
        )
    )
    if (
        user is None
        or not user.is_active
        or not user.secondary_password_hash
        or not verify_security_answer(security_answer, user.security_answer_hash)
        or len(secondary_password.encode("utf-8")) > 72
        or not pwd_context.verify(secondary_password, user.secondary_password_hash)
    ):
        return render(
            request,
            "forgot_password.html",
            error="Không xác minh được thông tin bảo mật.",
            success=None,
        )
    if error := password_policy_error(new_password):
        return render(request, "forgot_password.html", error=error, success=None)
    if new_password != confirm_password:
        return render(
            request,
            "forgot_password.html",
            error="Mật khẩu xác nhận không khớp.",
            success=None,
        )
    user.password_hash = pwd_context.hash(new_password)
    db.commit()
    return render(
        request,
        "forgot_password.html",
        error=None,
        success="Đã đổi mật khẩu. Bạn có thể đăng nhập bằng mật khẩu mới.",
    )


@app.post("/forgot-password/admin-request", response_class=HTMLResponse)
def request_admin_password_reset(
    request: Request,
    username: str = Form(..., max_length=30),
    email: str = Form(..., max_length=255),
    security_answer: str = Form(..., min_length=1, max_length=255),
    db: Session = Depends(get_db),
    _csrf: None = Depends(csrf_protected),
):
    user = db.scalar(
        select(User).where(
            func.lower(User.username) == username.strip().lower(),
            func.lower(User.email) == email.strip().lower(),
            User.role == "user",
        )
    )
    if user is None or not verify_security_answer(
        security_answer, user.security_answer_hash
    ):
        return render(
            request,
            "forgot_password.html",
            error="Thông tin xác minh không khớp với tài khoản.",
            success=None,
        )
    pending = db.scalar(
        select(PasswordResetRequest.id).where(
            PasswordResetRequest.user_id == user.id,
            PasswordResetRequest.status == "pending",
        )
    )
    if pending:
        return render(
            request,
            "forgot_password.html",
            error=None,
            success="Đã có yêu cầu đặt lại mật khẩu đang chờ Admin xử lý.",
        )
    db.add(PasswordResetRequest(user_id=user.id))
    db.add(
        Notification(
            user_id=user.id,
            message=f"Yêu cầu hỗ trợ đặt lại mật khẩu từ {user.username} ({user.email}) cần Admin duyệt.",
        )
    )
    db.commit()
    return render(
        request,
        "forgot_password.html",
        error=None,
        success="Đã gửi yêu cầu xác minh tới Admin.",
    )


@app.post("/logout")
def logout(_csrf: None = Depends(csrf_protected)):
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token")
    return response


@app.get("/account", response_class=HTMLResponse)
def account_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db.refresh(user, attribute_names=["package"])
    return render(request, "account.html", user=user, package=user.package)


@app.post("/account/profile")
def update_account_profile(
    full_name: str = Form(..., min_length=2, max_length=160),
    company_name: str = Form("", max_length=200),
    phone: str = Form("", max_length=40),
    address: str = Form("", max_length=2000),
    bank_account_number: str = Form("", max_length=100),
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    normalized_name = full_name.strip()
    if len(normalized_name) < 2:
        return RedirectResponse("/account?error=full_name", status_code=303)
    user.full_name = normalized_name
    user.company_name = company_name.strip()
    user.phone = phone.strip()
    user.address = address.strip()
    user.bank_account_number = bank_account_number.strip()
    db.commit()
    return RedirectResponse("/account?updated=1", status_code=303)


@app.post("/account/security")
def update_account_security(
    security_question: str = Form("", max_length=255),
    security_answer: str = Form("", max_length=255),
    secondary_password: str = Form("", max_length=128),
    confirm_secondary_password: str = Form("", max_length=128),
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if secondary_password:
        if error := password_policy_error(secondary_password):
            return RedirectResponse("/account?error=password_policy", status_code=303)
        if secondary_password != confirm_secondary_password:
            return RedirectResponse("/account?error=password_mismatch", status_code=303)
        if len(secondary_password.encode("utf-8")) > 72:
            return RedirectResponse("/account?error=password_policy", status_code=303)
        user.secondary_password_hash = pwd_context.hash(secondary_password)
    if security_answer:
        if not security_question.strip():
            return RedirectResponse("/account?error=security_question", status_code=303)
        user.security_question = security_question.strip()
        user.security_answer_hash = hash_security_answer(security_answer)
    elif security_question.strip() and not user.security_answer_hash:
        return RedirectResponse("/account?error=security_answer", status_code=303)
    db.commit()
    return RedirectResponse("/account?updated=1", status_code=303)


@app.get("/pricing", response_class=HTMLResponse)
def pricing_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    packages = db.scalars(select(Package).where(Package.is_active.is_(True)).order_by(Package.price)).all()
    requests = db.scalars(
        select(PaymentRequest)
        .options(selectinload(PaymentRequest.package))
        .where(PaymentRequest.user_id == user.id)
        .order_by(PaymentRequest.created_at.desc())
    ).all()
    banks = db.scalars(select(BankAccount).where(BankAccount.is_active.is_(True)).order_by(BankAccount.bank_name)).all()
    return render(
        request,
        "pricing.html",
        user=user,
        packages=packages,
        payment_requests=requests,
        banks=banks,
    )


@app.post("/subscribe/{package_id}")
def subscribe(
    package_id: int,
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    package = db.get(Package, package_id)
    bank = db.scalar(select(BankAccount).where(BankAccount.is_active.is_(True)).order_by(BankAccount.id))
    if package is None or not package.is_active:
        raise HTTPException(status_code=404, detail="Gói dịch vụ hiện không khả dụng.")
    if bank is None:
        return RedirectResponse("/pricing?error=no_bank", status_code=303)
    ref = "AP" + secrets.token_hex(5).upper()
    slug = package.name.upper().replace(" ", "")
    content = f"NAP {user.id} {slug} {ref} - {user.company_name or user.full_name}"
    payment = PaymentRequest(
        user_id=user.id,
        package_id=package.id,
        bank_account_id=bank.id,
        reference_code=ref,
        transfer_content=content[:255],
        amount=package.price,
        business_name=user.company_name or user.full_name,
        expires_at=utcnow() + timedelta(hours=2),
    )
    db.add(payment)
    db.commit()
    return RedirectResponse(f"/pricing?payment={payment.id}", status_code=303)


@app.post("/payments/{payment_id}/submitted")
def mark_payment_submitted(
    payment_id: int,
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    payment = db.scalar(
        select(PaymentRequest).where(PaymentRequest.id == payment_id, PaymentRequest.user_id == user.id)
    )
    if payment is None or payment.status != "created":
        raise HTTPException(status_code=404, detail="Không tìm thấy yêu cầu thanh toán chưa gửi.")
    payment.status = "pending"
    payment.submitted_at = utcnow()
    payment.expires_at = payment.submitted_at + timedelta(hours=2)
    db.commit()
    return RedirectResponse("/pricing?submitted=1", status_code=303)


@app.get("/app", response_class=HTMLResponse)
def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    customer_count = db.scalar(select(func.count(Customer.id)).where(Customer.owner_id == user.id)) or 0
    product_count = db.scalar(select(func.count(Product.id)).where(Product.owner_id == user.id)) or 0
    documents = db.scalars(
        select(Document)
        .options(selectinload(Document.customer))
        .where(Document.owner_id == user.id)
        .order_by(Document.created_at.desc())
        .limit(6)
    ).all()
    return render(
        request,
        "dashboard.html",
        user=user,
        customer_count=customer_count,
        product_count=product_count,
        documents=documents,
        packages=db.scalars(
            select(Package)
            .where(Package.is_active.is_(True))
            .order_by(Package.price)
        ).all(),
        can_use_workspace=subscription_is_active(user),
    )


@app.get("/customers", response_class=HTMLResponse)
def customers_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    customers = db.scalars(
        select(Customer).where(Customer.owner_id == user.id).order_by(Customer.name)
    ).all()
    return render(request, "customers.html", user=user, customers=customers)


@app.post("/customers")
def create_customer(
    name: str = Form(..., min_length=1, max_length=160),
    company: str = Form("", max_length=200),
    email: str = Form("", max_length=255),
    phone: str = Form("", max_length=50),
    address: str = Form("", max_length=2000),
    tax_code: str = Form("", max_length=50),
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    customer = Customer(
        owner_id=user.id,
        name=name.strip(),
        company=company.strip(),
        email=email.strip(),
        phone=phone.strip(),
        address=address.strip(),
        tax_code=tax_code.strip(),
    )
    db.add(customer)
    db.commit()
    return RedirectResponse("/customers?created=1", status_code=303)


@app.get("/products", response_class=HTMLResponse)
def products_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    products = db.scalars(
        select(Product).where(Product.owner_id == user.id).order_by(Product.name)
    ).all()
    return render(
        request,
        "products.html",
        user=user,
        products=products,
        can_manage=subscription_is_active(user),
    )


@app.post("/products")
def create_product(
    name: str = Form(..., min_length=1, max_length=180),
    description: str = Form("", max_length=2000),
    unit: str = Form("lần", max_length=40),
    unit_price: Decimal = Form(..., gt=0, le=MAX_AMOUNT),
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(require_subscription),
    db: Session = Depends(get_db),
):
    db.add(
        Product(
            owner_id=user.id,
            name=name.strip(),
            description=description.strip(),
            unit=unit.strip() or "lần",
            unit_price=unit_price,
        )
    )
    db.commit()
    return RedirectResponse("/products?created=1", status_code=303)


@app.get("/documents", response_class=HTMLResponse)
def documents_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    documents = db.scalars(
        select(Document)
        .options(selectinload(Document.customer))
        .where(Document.owner_id == user.id)
        .order_by(Document.created_at.desc())
    ).all()
    payment_requests = db.scalars(
        select(PaymentRequest)
        .options(selectinload(PaymentRequest.package))
        .where(PaymentRequest.user_id == user.id)
        .order_by(PaymentRequest.created_at.desc())
    ).all()
    return render(
        request,
        "documents.html",
        user=user,
        documents=documents,
        payment_requests=payment_requests,
        can_create=subscription_is_active(user),
    )


@app.get("/documents/new", response_class=HTMLResponse)
def new_document_page(
    request: Request,
    kind: str = "proposal",
    user: User = Depends(require_subscription),
    db: Session = Depends(get_db),
):
    if kind not in {"proposal", "invoice"}:
        raise HTTPException(status_code=400, detail="Loại tài liệu không hợp lệ.")
    customers = db.scalars(
        select(Customer).where(Customer.owner_id == user.id).order_by(Customer.name)
    ).all()
    products = db.scalars(
        select(Product).where(Product.owner_id == user.id, Product.is_active.is_(True)).order_by(Product.name)
    ).all()
    return render(
        request,
        "document_form.html",
        user=user,
        kind=kind,
        customers=customers,
        products=products,
        error=None,
    )


@app.post("/documents/new")
def create_document(
    request: Request,
    kind: str = Form(...),
    customer_id: int = Form(...),
    title: str = Form(..., min_length=1, max_length=200),
    item_product_ids: list[str] = Form(...),
    quantities: list[str] = Form(...),
    discount_percent: Decimal = Form(0, ge=0, le=100),
    tax_percent: Decimal = Form(0, ge=0, le=100),
    due_date: str = Form(""),
    notes: str = Form("", max_length=4000),
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(require_subscription),
    db: Session = Depends(get_db),
):
    customers = db.scalars(select(Customer).where(Customer.owner_id == user.id).order_by(Customer.name)).all()
    products = db.scalars(
        select(Product).where(Product.owner_id == user.id, Product.is_active.is_(True)).order_by(Product.name)
    ).all()
    if kind not in {"proposal", "invoice"}:
        raise HTTPException(status_code=400, detail="Loại tài liệu không hợp lệ.")
    customer = db.scalar(select(Customer).where(Customer.id == customer_id, Customer.owner_id == user.id))
    if customer is None or len(item_product_ids) != len(quantities):
        return render(
            request, "document_form.html", user=user, kind=kind, customers=customers,
            products=products, error="Chọn khách hàng và kiểm tra các dòng sản phẩm.",
        )
    if len(item_product_ids) > 100:
        return render(
            request, "document_form.html", user=user, kind=kind, customers=customers,
            products=products, error="Mỗi tài liệu có thể có tối đa 100 dòng sản phẩm.",
        )
    items: list[DocumentItem] = []
    subtotal = Decimal("0")
    try:
        for product_id_text, quantity_text in zip(item_product_ids, quantities):
            product = db.scalar(
                select(Product).where(
                    Product.id == int(product_id_text),
                    Product.owner_id == user.id,
                    Product.is_active.is_(True),
                )
            )
            quantity = Decimal(quantity_text)
            if product is None or quantity <= 0 or quantity > Decimal("1000000"):
                raise ValueError
            line_total = (quantity * product.unit_price).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            subtotal += line_total
            if subtotal > MAX_AMOUNT:
                raise ValueError
            items.append(
                DocumentItem(
                    description=product.name,
                    quantity=quantity,
                    unit=product.unit,
                    unit_price=product.unit_price,
                    line_total=line_total,
                )
            )
        if not items:
            raise ValueError
    except (ValueError, InvalidOperation):
        return render(
            request, "document_form.html", user=user, kind=kind, customers=customers,
            products=products, error="Một hoặc nhiều sản phẩm/số lượng không hợp lệ.",
        )
    discount = (subtotal * discount_percent / Decimal("100")).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    taxable = subtotal - discount
    total = (taxable + taxable * tax_percent / Decimal("100")).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    if total > MAX_AMOUNT:
        return render(
            request, "document_form.html", user=user, kind=kind, customers=customers,
            products=products, error="Tổng giá trị tài liệu vượt giới hạn lưu trữ.",
        )
    try:
        parsed_due_date = datetime.strptime(due_date, "%Y-%m-%d").replace(tzinfo=timezone.utc) if due_date else None
    except ValueError:
        return render(
            request, "document_form.html", user=user, kind=kind, customers=customers,
            products=products, error="Ngày đến hạn không hợp lệ.",
        )
    prefix = "BG" if kind == "proposal" else "HD"
    document_model = Proposal if kind == "proposal" else Invoice
    document = document_model(
        owner_id=user.id,
        customer_id=customer.id,
        document_type=kind,
        number=f"{prefix}-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}",
        title=title.strip(),
        due_date=parsed_due_date,
        subtotal=subtotal,
        discount_percent=discount_percent,
        tax_percent=tax_percent,
        total=total,
        notes=notes.strip(),
        items=items,
    )
    db.add(document)
    db.commit()
    return RedirectResponse(f"/documents/{document.id}", status_code=303)


@app.get("/documents/{document_id}", response_class=HTMLResponse)
def document_detail(
    document_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = get_owned_document(db, document_id, user.id)
    return render(request, "document_detail.html", user=user, document=document)


@app.post("/documents/{document_id}/status")
def update_document_status(
    document_id: int,
    status: str = Form(...),
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(require_subscription),
    db: Session = Depends(get_db),
):
    document = db.scalar(
        select(Document).where(Document.id == document_id, Document.owner_id == user.id)
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài liệu.")
    if not safe_next_status(document.status, status):
        raise HTTPException(status_code=400, detail="Không thể chuyển tài liệu sang trạng thái này.")
    document.status = status
    db.commit()
    return RedirectResponse(f"/documents/{document.id}", status_code=303)


def register_pdf_font() -> str:
    font_paths = [
        Path(os.getenv("PDF_FONT_PATH", "")) if os.getenv("PDF_FONT_PATH") else None,
        Path("C:/Windows/Fonts/arial.ttf"),
        Path("C:/Windows/Fonts/calibri.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    ]
    for font_path in font_paths:
        if font_path and font_path.is_file():
            pdfmetrics.registerFont(TTFont("InvoiceSans", str(font_path)))
            return "InvoiceSans"
    raise HTTPException(
        status_code=503,
        detail="Không tìm thấy font TTF hỗ trợ tiếng Việt. Hãy cấu hình biến môi trường PDF_FONT_PATH.",
    )


@app.get("/documents/{document_id}/pdf")
def document_pdf(
    document_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = get_owned_document(db, document_id, user.id)
    font = register_pdf_font()
    styles = getSampleStyleSheet()
    styles["Title"].fontName = font
    styles["Normal"].fontName = font
    styles["Heading2"].fontName = font
    content = [
        Paragraph(escape(document.title), styles["Title"]),
        Paragraph(f"<b>{document.number}</b> · {document.issue_date:%d/%m/%Y}", styles["Normal"]),
        Spacer(1, 8 * mm),
        Paragraph(f"<b>{escape(user.company_name or user.full_name)}</b>", styles["Heading2"]),
        Paragraph(
            f"Khách hàng: {escape(document.customer.company or document.customer.name)}<br/>"
            f"Người liên hệ: {escape(document.customer.name)}<br/>"
            f"Email: {escape(document.customer.email or '—')}<br/>"
            f"Trạng thái: {document.status}",
            styles["Normal"],
        ),
        Spacer(1, 7 * mm),
    ]
    rows = [["Sản phẩm / dịch vụ", "SL", "Đơn giá", "Thành tiền"]]
    for item in document.items:
        rows.append(
            [
                item.description,
                f"{item.quantity:g} {item.unit}",
                money(item.unit_price),
                money(item.line_total),
            ]
        )
    rows.extend(
        [
            ["", "", "Tạm tính", money(document.subtotal)],
            ["", "", f"Chiết khấu ({document.discount_percent}%)", money(document.subtotal * document.discount_percent / Decimal("100"))],
            ["", "", f"VAT ({document.tax_percent}%)", money((document.subtotal * (Decimal("1") - document.discount_percent / Decimal("100"))) * document.tax_percent / Decimal("100"))],
            ["", "", "TỔNG CỘNG", money(document.total)],
        ]
    )
    table = Table(rows, colWidths=[74 * mm, 26 * mm, 34 * mm, 40 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#162b49")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), font),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#dce3ed")),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    content.append(table)
    if document.notes:
        safe_notes = escape(document.notes).replace("\n", "<br/>")
        content.extend([Spacer(1, 7 * mm), Paragraph(f"Ghi chú: {safe_notes}", styles["Normal"])])
    content.extend([Spacer(1, 12 * mm), Paragraph("Cảm ơn Quý khách đã tin tưởng!", styles["Normal"])])
    from io import BytesIO

    buffer = BytesIO()
    SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm).build(content)
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{document.number}.pdf"'},
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    pending_count = db.scalar(
        select(func.count(PaymentRequest.id)).where(PaymentRequest.status == "pending")
    ) or 0
    user_count = db.scalar(select(func.count(User.id)).where(User.role == "user")) or 0
    payment_count = db.scalar(select(func.count(PaymentRequest.id))) or 0
    unread_notification_count = db.scalar(
        select(func.count(Notification.id)).where(Notification.is_read.is_(False))
    ) or 0
    notifications = db.scalars(
        select(Notification)
        .options(selectinload(Notification.user))
        .order_by(Notification.created_at.desc())
        .limit(10)
    ).all()
    payments = db.scalars(
        select(PaymentRequest)
        .options(selectinload(PaymentRequest.user), selectinload(PaymentRequest.package))
        .order_by(PaymentRequest.created_at.desc())
        .limit(8)
    ).all()
    banks = db.scalars(select(BankAccount).order_by(BankAccount.bank_name)).all()
    packages = db.scalars(select(Package).order_by(Package.price)).all()
    return render(
        request,
        "admin.html",
        user=admin,
        pending_count=pending_count,
        user_count=user_count,
        payment_count=payment_count,
        payments=payments,
        banks=banks,
        packages=packages,
        vn_banks=VN_BANKS,
        notifications=notifications,
        unread_notification_count=unread_notification_count,
    )


@app.post("/admin/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    notification = db.get(Notification, notification_id)
    if notification is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy thông báo.")
    notification.is_read = True
    db.commit()
    return RedirectResponse("/admin#notifications", status_code=303)


@app.get("/admin/payments", response_class=HTMLResponse)
def admin_payments_page(
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    payments = db.scalars(
        select(PaymentRequest)
        .options(
            selectinload(PaymentRequest.user),
            selectinload(PaymentRequest.package),
            selectinload(PaymentRequest.bank_account),
        )
        .order_by(PaymentRequest.created_at.desc())
    ).all()
    return render(request, "admin_payments.html", user=admin, payments=payments)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    users = db.scalars(
        select(User)
        .options(selectinload(User.package))
        .where(User.role == "user")
        .order_by(User.created_at.desc())
    ).all()
    reset_requests = db.scalars(
        select(PasswordResetRequest)
        .options(selectinload(PasswordResetRequest.user))
        .order_by(PasswordResetRequest.created_at.desc())
        .limit(50)
    ).all()
    packages = db.scalars(select(Package).where(Package.is_active.is_(True)).order_by(Package.price)).all()
    return render(
        request,
        "admin_users.html",
        user=admin,
        users=users,
        reset_requests=reset_requests,
        packages=packages,
    )


@app.post("/admin/users/{target_user_id}/manage")
def manage_user(
    target_user_id: int,
    action: str = Form(...),
    days: int = Form(30, ge=1, le=3650),
    balance: Decimal = Form(0, ge=0, le=MAX_BALANCE),
    expire_date: str = Form(""),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.scalar(
        select(User).where(User.id == target_user_id, User.role == "user")
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản người dùng.")
    if action == "activate":
        target.account_status = "active"
        target.is_active = True
    elif action == "deactivate":
        target.account_status = "inactive"
        target.is_active = False
    elif action == "suspend":
        target.account_status = "suspended"
        target.is_active = False
    elif action == "trial":
        package = db.scalar(select(Package).where(Package.name == "Cơ bản"))
        if package is None:
            raise HTTPException(status_code=503, detail="Chưa cấu hình gói Cơ bản.")
        target.package_id = package.id
        target.account_status = "active"
        target.is_active = True
        if expire_date:
            try:
                target.trial_expires_at = datetime.strptime(
                    expire_date, "%Y-%m-%d"
                ).replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            except ValueError:
                raise HTTPException(status_code=400, detail="Ngày hết hạn dùng thử không hợp lệ.") from None
        else:
            target.trial_expires_at = utcnow() + timedelta(days=days)
        target.subscription_expires_at = None
    elif action == "trial_off":
        target.trial_expires_at = None
    elif action == "extend":
        if target.package_id is None:
            package = db.scalar(select(Package).where(Package.name == "Cơ bản"))
            if package is None:
                raise HTTPException(status_code=503, detail="Chưa cấu hình gói Cơ bản.")
            target.package_id = package.id
        expiry = target.subscription_expires_at
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        target.subscription_expires_at = max(expiry, utcnow()) + timedelta(days=days) if expiry else utcnow() + timedelta(days=days)
        target.account_status = "active"
        target.is_active = True
    elif action == "set_balance":
        target.balance = balance.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    else:
        raise HTTPException(status_code=400, detail="Thao tác quản lý tài khoản không hợp lệ.")
    db.commit()
    return RedirectResponse("/admin/users?updated=1", status_code=303)


@app.post("/admin/users")
def create_user_by_admin(
    username: str = Form(..., min_length=3, max_length=30),
    email: str = Form(..., max_length=255),
    full_name: str = Form(..., min_length=2, max_length=160),
    company_name: str = Form("", max_length=200),
    password: str = Form(..., max_length=128),
    role: str = Form("user"),
    expire_date: str = Form(""),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    username = username.strip().lower()
    email = email.strip().lower()
    if role not in {"user", "admin"}:
        raise HTTPException(status_code=400, detail="Vai trò tài khoản không hợp lệ.")
    if not USERNAME_PATTERN.fullmatch(username):
        raise HTTPException(status_code=400, detail="Username cần 3–30 ký tự hợp lệ.")
    if not GMAIL_PATTERN.fullmatch(email):
        raise HTTPException(status_code=400, detail=GMAIL_ERROR)
    if role == "user" and role_is_reserved(email):
        raise HTTPException(status_code=400, detail="Email Admin được dành riêng cho quản trị viên.")
    if error := password_policy_error(password):
        raise HTTPException(status_code=400, detail=error)
    if db.scalar(select(User.id).where(func.lower(User.username) == username)):
        raise HTTPException(status_code=409, detail="Username đã tồn tại.")
    if db.scalar(select(User.id).where(func.lower(User.email) == email)):
        raise HTTPException(status_code=409, detail="Email đã tồn tại.")
    trial_expiry = None
    if expire_date:
        try:
            trial_expiry = datetime.strptime(expire_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Ngày hết hạn dùng thử không hợp lệ.") from None
    new_user = User(
        username=username,
        email=email,
        full_name=full_name.strip(),
        company_name=company_name.strip(),
        password_hash=pwd_context.hash(password),
        role=role,
        trial_expires_at=trial_expiry,
    )
    if trial_expiry:
        package = db.scalar(select(Package).where(Package.name == "Cơ bản"))
        if package is None:
            raise HTTPException(status_code=503, detail="Chưa cấu hình gói Cơ bản.")
        new_user.package_id = package.id
    db.add(new_user)
    db.commit()
    return RedirectResponse("/admin/users?created=1", status_code=303)


@app.post("/admin/users/{target_user_id}/edit")
def edit_user_by_admin(
    target_user_id: int,
    username: str = Form(..., min_length=3, max_length=30),
    email: str = Form(..., max_length=255),
    full_name: str = Form(..., min_length=2, max_length=160),
    company_name: str = Form("", max_length=200),
    password: str = Form("", max_length=128),
    expire_date: str = Form(""),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, target_user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")
    username = username.strip().lower()
    email = email.strip().lower()
    if not USERNAME_PATTERN.fullmatch(username) or not GMAIL_PATTERN.fullmatch(email):
        raise HTTPException(status_code=400, detail="Username hoặc địa chỉ Gmail không hợp lệ.")
    if db.scalar(
        select(User.id).where(
            func.lower(User.username) == username, User.id != target.id
        )
    ):
        raise HTTPException(status_code=409, detail="Username đã tồn tại.")
    if db.scalar(
        select(User.id).where(func.lower(User.email) == email, User.id != target.id)
    ):
        raise HTTPException(status_code=409, detail="Email đã tồn tại.")
    if target.id != admin.id and role_is_reserved(email):
        raise HTTPException(
            status_code=400,
            detail="Email Admin được dành riêng cho tài khoản quản trị.",
        )
    if password and (error := password_policy_error(password)):
        raise HTTPException(status_code=400, detail=error)
    trial_expiry = None
    if expire_date:
        try:
            trial_expiry = datetime.strptime(expire_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Ngày hết hạn dùng thử không hợp lệ.") from None
    target.username = username
    target.email = email
    target.full_name = full_name.strip()
    target.company_name = company_name.strip()
    if password:
        target.password_hash = pwd_context.hash(password)
    target.trial_expires_at = trial_expiry
    db.commit()
    return RedirectResponse("/admin/users?updated=1", status_code=303)


@app.post("/admin/users/{target_user_id}/delete")
def delete_user_by_admin(
    target_user_id: int,
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, target_user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="Không thể xóa tài khoản Admin đang đăng nhập.")
    document_ids = select(Document.id).where(Document.owner_id == target.id)
    db.execute(delete(DocumentItem).where(DocumentItem.document_id.in_(document_ids)))
    db.execute(delete(Document).where(Document.owner_id == target.id))
    db.execute(delete(Customer).where(Customer.owner_id == target.id))
    db.execute(delete(Product).where(Product.owner_id == target.id))
    db.execute(delete(PaymentRequest).where(PaymentRequest.user_id == target.id))
    db.execute(delete(Notification).where(Notification.user_id == target.id))
    db.execute(delete(PasswordResetRequest).where(PasswordResetRequest.user_id == target.id))
    db.delete(target)
    db.commit()
    return RedirectResponse("/admin/users?deleted=1", status_code=303)


def role_is_reserved(email: str) -> bool:
    return email.strip().lower() == os.getenv("ADMIN_EMAIL", "admin@gmail.com").strip().lower()


@app.post("/admin/packages")
def create_package(
    name: str = Form(..., min_length=2, max_length=80),
    description: str = Form("", max_length=4000),
    price: Decimal = Form(..., ge=0, le=MAX_AMOUNT),
    duration_days: int = Form(30, ge=1, le=3650),
    customer_limit: int = Form(100, ge=1, le=10000000),
    document_limit: int = Form(100, ge=1, le=10000000),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    name = name.strip()
    if db.scalar(select(Package.id).where(func.lower(Package.name) == name.lower())):
        raise HTTPException(status_code=409, detail="Tên gói dịch vụ đã tồn tại.")
    db.add(
        Package(
            name=name,
            description=description.strip(),
            price=price.quantize(Decimal("0.01")),
            duration_days=duration_days,
            customer_limit=customer_limit,
            document_limit=document_limit,
        )
    )
    db.commit()
    return RedirectResponse("/admin?package_updated=1#packages", status_code=303)


@app.post("/admin/packages/{package_id}/edit")
def edit_package(
    package_id: int,
    name: str = Form(..., min_length=2, max_length=80),
    description: str = Form("", max_length=4000),
    price: Decimal = Form(..., ge=0, le=MAX_AMOUNT),
    duration_days: int = Form(30, ge=1, le=3650),
    customer_limit: int = Form(100, ge=1, le=10000000),
    document_limit: int = Form(100, ge=1, le=10000000),
    is_active: bool = Form(False),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    package = db.get(Package, package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy gói dịch vụ.")
    name = name.strip()
    if db.scalar(
        select(Package.id).where(
            func.lower(Package.name) == name.lower(), Package.id != package.id
        )
    ):
        raise HTTPException(status_code=409, detail="Tên gói dịch vụ đã tồn tại.")
    package.name = name
    package.description = description.strip()
    package.price = price.quantize(Decimal("0.01"))
    package.duration_days = duration_days
    package.customer_limit = customer_limit
    package.document_limit = document_limit
    package.is_active = is_active
    db.commit()
    return RedirectResponse("/admin?package_updated=1#packages", status_code=303)


@app.post("/admin/packages/{package_id}/delete")
def delete_package(
    package_id: int,
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    package = db.get(Package, package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy gói dịch vụ.")
    used = db.scalar(
        select(User.id).where(User.package_id == package.id).limit(1)
    ) or db.scalar(
        select(PaymentRequest.id).where(PaymentRequest.package_id == package.id).limit(1)
    )
    seeded_package = any(seed["name"] == package.name for seed in PACKAGE_SEEDS)
    if used or seeded_package:
        package.is_active = False
        db.commit()
        return RedirectResponse("/admin?package_archived=1#packages", status_code=303)
    db.delete(package)
    db.commit()
    return RedirectResponse("/admin?package_deleted=1#packages", status_code=303)


@app.post("/admin/password-resets/{reset_id}/review")
def review_password_reset(
    reset_id: int,
    decision: str = Form(...),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    admin_note: str = Form("", max_length=1000),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    reset_request = db.scalar(
        select(PasswordResetRequest)
        .options(selectinload(PasswordResetRequest.user))
        .where(PasswordResetRequest.id == reset_id)
    )
    if reset_request is None or reset_request.status != "pending":
        raise HTTPException(status_code=404, detail="Yêu cầu đặt lại mật khẩu không còn chờ duyệt.")
    if decision not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="Quyết định không hợp lệ.")
    if decision == "approve":
        if error := password_policy_error(new_password):
            return RedirectResponse("/admin/users?reset_error=password_policy", status_code=303)
        if new_password != confirm_password:
            return RedirectResponse("/admin/users?reset_error=password_mismatch", status_code=303)
        reset_request.user.password_hash = pwd_context.hash(new_password)
        reset_request.status = "approved"
    else:
        reset_request.status = "rejected"
    reset_request.admin_note = admin_note.strip()
    reset_request.reviewed_at = utcnow()
    db.commit()
    return RedirectResponse("/admin/users?reset_reviewed=1", status_code=303)


@app.post("/admin/payments/{payment_id}/review")
def review_payment(
    payment_id: int,
    decision: str = Form(...),
    admin_note: str = Form("", max_length=1000),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if decision not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="Quyết định không hợp lệ.")
    payment = db.scalar(
        select(PaymentRequest)
        .options(selectinload(PaymentRequest.user), selectinload(PaymentRequest.package))
        .where(PaymentRequest.id == payment_id)
    )
    if payment is None or payment.status != "pending":
        raise HTTPException(status_code=404, detail="Yêu cầu không còn ở trạng thái chờ duyệt.")
    deadline = payment.expires_at
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    if deadline <= datetime.now(timezone.utc):
        payment.status = "expired"
        payment.reviewed_at = utcnow()
        payment.admin_note = "Yêu cầu đã quá thời hạn chờ duyệt 2 giờ."
        db.commit()
        return RedirectResponse("/admin/payments?expired=1", status_code=303)
    payment.reviewed_at = utcnow()
    payment.admin_note = admin_note.strip()
    if decision == "approve":
        payment.status = "approved"
        payment.user.package_id = payment.package_id
        current_expiry = payment.user.subscription_expires_at
        if current_expiry and current_expiry.tzinfo is None:
            current_expiry = current_expiry.replace(tzinfo=timezone.utc)
        extension_from = max(current_expiry, utcnow()) if current_expiry else utcnow()
        payment.user.subscription_expires_at = extension_from + timedelta(days=payment.package.duration_days)
    else:
        payment.status = "rejected"
    db.commit()
    return RedirectResponse("/admin/payments?reviewed=1", status_code=303)


@app.post("/admin/banks")
def create_bank_account(
    bank_name: str = Form(..., min_length=2, max_length=100),
    account_number: str = Form(..., min_length=3, max_length=100),
    account_holder: str = Form(..., min_length=2, max_length=160),
    transfer_instruction: str = Form("", max_length=255),
    qr_code_url: str = Form("", max_length=1000),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if qr_code_url and not qr_code_url.strip().lower().startswith("https://"):
        raise HTTPException(status_code=400, detail="QR Code phải dùng URL HTTPS.")
    db.add(
        BankAccount(
            bank_name=bank_name.strip(),
            account_number=account_number.strip(),
            account_holder=account_holder.strip(),
            transfer_instruction=transfer_instruction.strip(),
            qr_code_url=qr_code_url.strip(),
        )
    )
    db.commit()
    return RedirectResponse("/admin?bank_added=1", status_code=303)


@app.post("/admin/banks/{bank_id}/edit")
def edit_bank_account(
    bank_id: int,
    bank_name: str = Form(..., min_length=2, max_length=100),
    account_number: str = Form(..., min_length=3, max_length=100),
    account_holder: str = Form(..., min_length=2, max_length=160),
    transfer_instruction: str = Form("", max_length=255),
    qr_code_url: str = Form("", max_length=1000),
    is_active: bool = Form(False),
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if qr_code_url and not qr_code_url.strip().lower().startswith("https://"):
        raise HTTPException(status_code=400, detail="QR Code phải dùng URL HTTPS.")
    bank = db.get(BankAccount, bank_id)
    if bank is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản ngân hàng.")
    bank.bank_name = bank_name.strip()
    bank.account_number = account_number.strip()
    bank.account_holder = account_holder.strip()
    bank.transfer_instruction = transfer_instruction.strip()
    bank.qr_code_url = qr_code_url.strip()
    bank.is_active = is_active
    db.commit()
    return RedirectResponse("/admin?bank_updated=1#banks", status_code=303)


@app.post("/admin/banks/{bank_id}/delete")
def delete_bank_account(
    bank_id: int,
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    bank = db.get(BankAccount, bank_id)
    if bank is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản ngân hàng.")
    has_payment_history = db.scalar(
        select(PaymentRequest.id)
        .where(PaymentRequest.bank_account_id == bank_id)
        .limit(1)
    )
    if has_payment_history:
        bank.is_active = False
        db.commit()
        return RedirectResponse("/admin?bank_archived=1#banks", status_code=303)
    db.delete(bank)
    db.commit()
    return RedirectResponse("/admin?bank_deleted=1#banks", status_code=303)


@app.post("/admin/banks/{bank_id}/toggle")
def toggle_bank(
    bank_id: int,
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    bank = db.get(BankAccount, bank_id)
    if bank is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản ngân hàng.")
    bank.is_active = not bank.is_active
    db.commit()
    return RedirectResponse("/admin?bank_updated=1", status_code=303)


def get_api_user(request: Request, db: Session) -> User:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Thiếu Bearer access token.")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub", ""))
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Access token không hợp lệ hoặc đã hết hạn.") from None
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.account_status != "active":
        raise HTTPException(status_code=403, detail="Tài khoản đã bị khóa hoặc ngừng hoạt động.")
    return user


def api_require_subscription(user: User) -> None:
    if not subscription_is_active(user):
        raise HTTPException(status_code=403, detail="Gói dịch vụ đã hết hạn hoặc chưa được kích hoạt.")


@app.post("/api/auth/login")
def api_login(payload: DesktopLoginPayload, db: Session = Depends(get_db)):
    identifier = payload.identifier.strip().lower()
    user = db.scalar(
        select(User).where(
            or_(
                func.lower(User.email) == identifier,
                func.lower(User.username) == identifier,
            )
        )
    )
    if (
        user is None
        or not user.is_active
        or user.account_status != "active"
        or len(payload.password.encode("utf-8")) > 72
        or not pwd_context.verify(payload.password, user.password_hash)
    ):
        raise HTTPException(status_code=401, detail="Tên đăng nhập hoặc mật khẩu không chính xác.")
    return {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
        },
    }


@app.get("/api/me")
def api_me(request: Request, db: Session = Depends(get_db)):
    user = get_api_user(request, db)
    now = datetime.now(timezone.utc)
    future_expiries = []
    for expiry in (user.trial_expires_at, user.subscription_expires_at):
        if expiry is None:
            continue
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry > now:
            future_expiries.append(expiry)
    expires_at = max(future_expiries) if future_expiries else None
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "company_name": user.company_name,
        "role": user.role,
        "subscription_active": subscription_is_active(user),
        "package": user.package.name if user.package else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": max(0, (expires_at.date() - now.date()).days) if expires_at else None,
    }


@app.get("/api/packages")
def api_packages(db: Session = Depends(get_db)):
    return [
        {
            "id": package.id,
            "name": package.name,
            "description": package.description,
            "price": str(package.price),
            "duration_days": package.duration_days,
            "customer_limit": package.customer_limit,
            "document_limit": package.document_limit,
        }
        for package in db.scalars(
            select(Package).where(Package.is_active.is_(True)).order_by(Package.price)
        ).all()
    ]


@app.get("/api/customers")
def api_customers(request: Request, db: Session = Depends(get_db)):
    user = get_api_user(request, db)
    return [
        {
            "id": row.id,
            "name": row.name,
            "company": row.company,
            "email": row.email,
            "phone": row.phone,
            "address": row.address,
            "tax_code": row.tax_code,
        }
        for row in db.scalars(
            select(Customer).where(Customer.owner_id == user.id).order_by(Customer.name)
        ).all()
    ]


@app.post("/api/customers", status_code=201)
def api_create_customer(
    payload: DesktopCustomerPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_api_user(request, db)
    customer = Customer(
        owner_id=user.id,
        name=payload.name.strip(),
        company=payload.company.strip(),
        email=payload.email.strip(),
        phone=payload.phone.strip(),
        address=payload.address.strip(),
        tax_code=payload.tax_code.strip(),
    )
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return {"id": customer.id, "name": customer.name, "company": customer.company}


@app.get("/api/products")
def api_products(request: Request, db: Session = Depends(get_db)):
    user = get_api_user(request, db)
    return [
        {
            "id": row.id,
            "name": row.name,
            "description": row.description,
            "unit": row.unit,
            "unit_price": str(row.unit_price),
            "is_active": row.is_active,
        }
        for row in db.scalars(
            select(Product).where(Product.owner_id == user.id).order_by(Product.name)
        ).all()
    ]


@app.post("/api/products", status_code=201)
def api_create_product(
    payload: DesktopProductPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_api_user(request, db)
    api_require_subscription(user)
    product = Product(
        owner_id=user.id,
        name=payload.name.strip(),
        description=payload.description.strip(),
        unit=payload.unit.strip() or "lần",
        unit_price=payload.unit_price.quantize(Decimal("0.01")),
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    return {"id": product.id, "name": product.name, "unit_price": str(product.unit_price)}


@app.get("/api/documents")
def api_documents(request: Request, db: Session = Depends(get_db)):
    user = get_api_user(request, db)
    return [
        {
            "id": document.id,
            "number": document.number,
            "type": document.document_type,
            "title": document.title,
            "customer": document.customer.company or document.customer.name,
            "status": document.status,
            "total": str(document.total),
            "created_at": document.created_at.isoformat(),
        }
        for document in db.scalars(
            select(Document)
            .options(selectinload(Document.customer))
            .where(Document.owner_id == user.id)
            .order_by(Document.created_at.desc())
        ).all()
    ]


@app.post("/api/documents", status_code=201)
def api_create_document(
    payload: DesktopDocumentPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_api_user(request, db)
    api_require_subscription(user)
    if payload.kind not in {"proposal", "invoice"}:
        raise HTTPException(status_code=422, detail="Loại tài liệu phải là proposal hoặc invoice.")
    customer = db.scalar(
        select(Customer).where(
            Customer.id == payload.customer_id, Customer.owner_id == user.id
        )
    )
    if customer is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy khách hàng của tài khoản.")
    items: list[DocumentItem] = []
    subtotal = Decimal("0")
    for line in payload.items:
        product = db.scalar(
            select(Product).where(
                Product.id == line.product_id,
                Product.owner_id == user.id,
                Product.is_active.is_(True),
            )
        )
        if product is None:
            raise HTTPException(status_code=404, detail=f"Không tìm thấy sản phẩm {line.product_id}.")
        line_total = (line.quantity * product.unit_price).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        subtotal += line_total
        if subtotal > MAX_AMOUNT:
            raise HTTPException(status_code=422, detail="Tổng giá trị vượt giới hạn.")
        items.append(
            DocumentItem(
                description=product.name,
                quantity=line.quantity,
                unit=product.unit,
                unit_price=product.unit_price,
                line_total=line_total,
            )
        )
    discount = (subtotal * payload.discount_percent / Decimal("100")).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    taxable = subtotal - discount
    total = (
        taxable + taxable * payload.tax_percent / Decimal("100")
    ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if total > MAX_AMOUNT:
        raise HTTPException(status_code=422, detail="Tổng giá trị vượt giới hạn.")
    prefix = "BG" if payload.kind == "proposal" else "HD"
    document_model = Proposal if payload.kind == "proposal" else Invoice
    document = document_model(
        owner_id=user.id,
        customer_id=customer.id,
        document_type=payload.kind,
        number=f"{prefix}-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}",
        title=payload.title.strip(),
        subtotal=subtotal,
        discount_percent=payload.discount_percent,
        tax_percent=payload.tax_percent,
        total=total,
        notes=payload.notes.strip(),
        items=items,
    )
    db.add(document)
    db.commit()
    db.refresh(document)
    return {
        "id": document.id,
        "number": document.number,
        "type": document.document_type,
        "total": str(document.total),
    }


@app.patch("/api/documents/{document_id}/status")
def api_update_document_status(
    document_id: int,
    payload: DesktopDocumentStatusPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_api_user(request, db)
    api_require_subscription(user)
    document = db.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.owner_id == user.id,
        )
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài liệu.")
    if not safe_next_status(document.status, payload.status):
        raise HTTPException(
            status_code=400,
            detail=f"Không thể chuyển trạng thái {document.status} sang {payload.status}.",
        )
    document.status = payload.status
    db.commit()
    return {"id": document.id, "status": document.status}

@app.get("/health")
def health():
    return {"status": "ok"}
