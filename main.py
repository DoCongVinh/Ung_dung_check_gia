"""Auto Proposal & Invoice Generator - FastAPI application."""

import os
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
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from models import (
    BankAccount,
    Base,
    Customer,
    Document,
    DocumentItem,
    Invoice,
    Package,
    PaymentRequest,
    Product,
    Proposal,
    User,
    utcnow,
)
from database import SessionLocal, engine


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

app = FastAPI(title="Auto Proposal & Invoice Generator", version="1.0.0")
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
    return templates.TemplateResponse(
        request=request,
        name=template,
        context=context,
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
    if user is None or not user.is_active:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập khu vực quản trị.")
    return user


def subscription_is_active(user: User) -> bool:
    if user.role == "admin":
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
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        for seed in PACKAGE_SEEDS:
            package = db.scalar(select(Package).where(Package.name == seed["name"]))
            if package is None:
                db.add(Package(**seed))
        db.commit()
        admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        admin_password = os.getenv("ADMIN_PASSWORD", "")
        if admin_email and admin_password:
            admin = db.scalar(select(User).where(User.email == admin_email))
            if admin is None:
                db.add(
                    User(
                        email=admin_email,
                        password_hash=pwd_context.hash(admin_password),
                        full_name=os.getenv("ADMIN_NAME", "Quản trị viên"),
                        role="admin",
                    )
                )
                db.commit()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render(request, "landing.html")


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return render(request, "auth.html", mode="register", error=None)


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    db: Session = Depends(get_db),
    _csrf: None = Depends(csrf_protected),
    full_name: str = Form(..., min_length=2, max_length=160),
    company_name: str = Form("", max_length=200),
    email: str = Form(..., max_length=255),
    password: str = Form(..., min_length=10, max_length=72),
):
    normalized_email = email.strip().lower()
    if "@" not in normalized_email or len(password.encode("utf-8")) > 72:
        return render(request, "auth.html", mode="register", error="Email hoặc mật khẩu không hợp lệ.")
    if db.scalar(select(User.id).where(User.email == normalized_email)):
        return render(request, "auth.html", mode="register", error="Email này đã được đăng ký.")
    user = User(
        email=normalized_email,
        full_name=full_name.strip(),
        company_name=company_name.strip(),
        password_hash=pwd_context.hash(password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return render(request, "auth.html", mode="register", error="Email này đã được đăng ký.")
    return RedirectResponse("/login?registered=1", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, registered: bool = False):
    return render(request, "auth.html", mode="login", error=None, registered=registered)


@app.post("/login")
def login(
    request: Request,
    db: Session = Depends(get_db),
    _csrf: None = Depends(csrf_protected),
    email: str = Form(...),
    password: str = Form(...),
):
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if (
        user is None
        or not user.is_active
        or len(password.encode("utf-8")) > 72
        or not pwd_context.verify(password, user.password_hash)
    ):
        return render(request, "auth.html", mode="login", error="Email hoặc mật khẩu không chính xác.")
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


@app.post("/logout")
def logout(_csrf: None = Depends(csrf_protected)):
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token")
    return response


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.refresh(user, attribute_names=["package"])
    return render(request, "account.html", user=user, package=user.package)


@app.post("/account")
def update_account(
    full_name: str = Form(..., min_length=2, max_length=160),
    company_name: str = Form("", max_length=200),
    _csrf: None = Depends(csrf_protected),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user.full_name = full_name.strip()
    user.company_name = company_name.strip()
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
    if package is None or not package.is_active or bank is None:
        raise HTTPException(status_code=400, detail="Gói dịch vụ hoặc tài khoản nhận tiền hiện không khả dụng.")
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
    user: User = Depends(require_subscription),
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
    )


@app.get("/customers", response_class=HTMLResponse)
def customers_page(
    request: Request,
    user: User = Depends(require_subscription),
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
    user: User = Depends(require_subscription),
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
    user: User = Depends(require_subscription),
    db: Session = Depends(get_db),
):
    products = db.scalars(
        select(Product).where(Product.owner_id == user.id).order_by(Product.name)
    ).all()
    return render(request, "products.html", user=user, products=products)


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
    user: User = Depends(require_subscription),
    db: Session = Depends(get_db),
):
    documents = db.scalars(
        select(Document)
        .options(selectinload(Document.customer))
        .where(Document.owner_id == user.id)
        .order_by(Document.created_at.desc())
    ).all()
    return render(request, "documents.html", user=user, documents=documents)


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
    user: User = Depends(require_subscription),
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
    user: User = Depends(require_subscription),
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
    )


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
    _csrf: None = Depends(csrf_protected),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db.add(
        BankAccount(
            bank_name=bank_name.strip(),
            account_number=account_number.strip(),
            account_holder=account_holder.strip(),
            transfer_instruction=transfer_instruction.strip(),
        )
    )
    db.commit()
    return RedirectResponse("/admin?bank_added=1", status_code=303)


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


@app.get("/health")
def health():
    return {"status": "ok"}
