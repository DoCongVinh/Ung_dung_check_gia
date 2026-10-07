"""Desktop companion for Vinh Ứng dụng tra cứu."""

from __future__ import annotations

import json
import os
import tkinter as tk
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime
from tkinter import messagebox, ttk
from typing import Any


DEFAULT_SERVER = os.getenv("VINH_APP_SERVER", "http://127.0.0.1:8000").rstrip("/")


class ApiClient:
    def __init__(self, server: str) -> None:
        self.server = server.rstrip("/")
        self.token = ""

    def request(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            f"{self.server}{endpoint}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            try:
                detail = json.loads(error.read().decode("utf-8")).get("detail")
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                detail = None
            raise RuntimeError(str(detail or f"Máy chủ trả về HTTP {error.code}.")) from None
        except (urllib.error.URLError, TimeoutError) as error:
            raise RuntimeError(f"Không kết nối được máy chủ: {error}") from None
        if not raw:
            return None
        return json.loads(raw.decode("utf-8"))

    def login(self, identifier: str, password: str) -> dict[str, Any]:
        result = self.request(
            "POST",
            "/api/auth/login",
            {"identifier": identifier, "password": password},
        )
        self.token = result["access_token"]
        return self.request("GET", "/api/me")


class PlaceholderEntry(ttk.Entry):
    def __init__(self, parent: tk.Misc, placeholder: str) -> None:
        super().__init__(parent, width=16)
        self.placeholder = placeholder
        self.insert(0, placeholder)
        self.bind("<FocusIn>", self._clear)
        self.bind("<FocusOut>", self._restore)

    def _clear(self, _event: tk.Event) -> None:
        if self.get() == self.placeholder:
            self.delete(0, "end")

    def _restore(self, _event: tk.Event) -> None:
        if not self.get().strip():
            self.insert(0, self.placeholder)

    def value(self) -> str:
        current = self.get().strip()
        return "" if current == self.placeholder else current

    def reset(self) -> None:
        self.delete(0, "end")
        self.insert(0, self.placeholder)


class VinhDesktopApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Vinh Ứng dụng tra cứu")
        self.root.geometry("1020x700")
        self.root.minsize(820, 580)
        self.root.configure(bg="#f4f6fb")
        self.api = ApiClient(DEFAULT_SERVER)
        self.profile: dict[str, Any] = {}
        self._build_login()

    def _build_login(self) -> None:
        self.login_frame = ttk.Frame(self.root, padding=34)
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(
            self.login_frame,
            text="Vinh Ứng dụng tra cứu",
            font=("Segoe UI", 21, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
        ttk.Label(
            self.login_frame,
            text="Đăng nhập bằng tài khoản Web để mở workspace trên laptop.",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 20))
        ttk.Label(self.login_frame, text="Địa chỉ Web").grid(row=2, column=0, sticky="w", pady=5)
        self.server_entry = ttk.Entry(self.login_frame, width=48)
        self.server_entry.insert(0, DEFAULT_SERVER)
        self.server_entry.grid(row=2, column=1, sticky="ew", pady=5)
        ttk.Label(self.login_frame, text="Email hoặc username").grid(row=3, column=0, sticky="w", pady=5)
        self.identifier_entry = ttk.Entry(self.login_frame, width=48)
        self.identifier_entry.grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Label(self.login_frame, text="Mật khẩu").grid(row=4, column=0, sticky="w", pady=5)
        self.password_entry = ttk.Entry(self.login_frame, width=48, show="•")
        self.password_entry.grid(row=4, column=1, sticky="ew", pady=5)
        self.password_entry.bind("<Return>", lambda _event: self._login())
        ttk.Button(self.login_frame, text="Đăng nhập", command=self._login).grid(
            row=5, column=1, sticky="e", pady=(17, 0)
        )
        self.login_frame.columnconfigure(1, weight=1)

    def _login(self) -> None:
        server = self.server_entry.get().strip().rstrip("/")
        identifier = self.identifier_entry.get().strip()
        password = self.password_entry.get()
        if not server.startswith(("http://", "https://")):
            messagebox.showerror("Địa chỉ máy chủ", "Địa chỉ cần bắt đầu bằng http:// hoặc https://.")
            return
        if not identifier or not password:
            messagebox.showerror("Thiếu thông tin", "Hãy nhập tài khoản và mật khẩu.")
            return
        self.api = ApiClient(server)
        try:
            self.profile = self.api.login(identifier, password)
        except (RuntimeError, KeyError, json.JSONDecodeError) as error:
            messagebox.showerror("Không thể đăng nhập", str(error))
            return
        self.login_frame.destroy()
        self._build_workspace()

    def _build_workspace(self) -> None:
        header = ttk.Frame(self.root, padding=(20, 14))
        header.pack(fill="x")
        ttk.Label(
            header,
            text=f"Xin chào, {self.profile.get('full_name') or self.profile.get('username')}",
            font=("Segoe UI", 16, "bold"),
        ).pack(side="left")
        ttk.Button(header, text="Mở toàn bộ ứng dụng Web", command=self._open_web).pack(side="right")
        self.notice = tk.Label(
            self.root,
            anchor="w",
            justify="left",
            padx=14,
            pady=10,
            font=("Segoe UI", 10, "bold"),
        )
        self.notice.pack(fill="x", padx=20, pady=(0, 10))
        self._show_expiry_notice()

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.customer_tab = ttk.Frame(self.tabs, padding=14)
        self.product_tab = ttk.Frame(self.tabs, padding=14)
        self.document_tab = ttk.Frame(self.tabs, padding=14)
        self.tabs.add(self.customer_tab, text="Khách hàng")
        self.tabs.add(self.product_tab, text="Sản phẩm / dịch vụ")
        self.tabs.add(self.document_tab, text="Báo giá / hóa đơn")
        self._build_customers()
        self._build_products()
        self._build_documents()
        self._run(self.refresh_all)

    def _show_expiry_notice(self) -> None:
        expires_at = self.profile.get("expires_at")
        days_left = self.profile.get("days_left")
        if not self.profile.get("subscription_active"):
            text = "Gói dịch vụ đã hết hạn hoặc chưa được kích hoạt. Vui lòng đăng ký/gia hạn để tiếp tục sử dụng."
            color = "#a52c20"
            background = "#ffe5df"
        elif days_left is not None and days_left < 5:
            try:
                expiry = datetime.fromisoformat(expires_at).astimezone().strftime("%d/%m/%Y")
            except (ValueError, TypeError):
                expiry = expires_at or "sắp tới"
            text = f"Gói dịch vụ của bạn sắp hết hạn vào ngày {expiry}. Vui lòng gia hạn để tiếp tục sử dụng!"
            color = "#8b5312"
            background = "#fff0d1"
        else:
            self.notice.pack_forget()
            return
        self.notice.configure(text=text, fg=color, bg=background)

    def _open_web(self) -> None:
        webbrowser.open(self.api.server)

    def _build_customers(self) -> None:
        ttk.Label(self.customer_tab, text="Danh bạ khách hàng", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        form = ttk.Frame(self.customer_tab, padding=(0, 12))
        form.pack(fill="x")
        self.customer_name = self._entry(form, "Tên khách hàng")
        self.customer_company = self._entry(form, "Doanh nghiệp")
        self.customer_email = self._entry(form, "Email")
        ttk.Button(form, text="Thêm khách hàng", command=self._add_customer).pack(side="left", padx=5)
        self.customer_tree = self._tree(
            self.customer_tab,
            ("id", "name", "company", "email"),
            ("ID", "Tên", "Doanh nghiệp", "Email"),
        )

    def _build_products(self) -> None:
        ttk.Label(self.product_tab, text="Danh mục sản phẩm / dịch vụ", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        form = ttk.Frame(self.product_tab, padding=(0, 12))
        form.pack(fill="x")
        self.product_name = self._entry(form, "Tên sản phẩm")
        self.product_price = self._entry(form, "Đơn giá (₫)")
        self.product_unit = self._entry(form, "Đơn vị")
        ttk.Button(form, text="Thêm sản phẩm", command=self._add_product).pack(side="left", padx=5)
        self.product_tree = self._tree(
            self.product_tab,
            ("id", "name", "unit", "unit_price"),
            ("ID", "Tên sản phẩm", "Đơn vị", "Đơn giá (₫)"),
        )

    def _build_documents(self) -> None:
        ttk.Label(self.document_tab, text="Tạo tài liệu", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        form = ttk.Frame(self.document_tab, padding=(0, 12))
        form.pack(fill="x")
        self.doc_kind = ttk.Combobox(form, values=("proposal", "invoice"), state="readonly", width=13)
        self.doc_kind.set("proposal")
        self.doc_kind.pack(side="left", padx=5)
        self.doc_customer_id = self._entry(form, "ID khách hàng")
        self.doc_product_id = self._entry(form, "ID sản phẩm")
        self.doc_quantity = self._entry(form, "Số lượng")
        self.doc_title = self._entry(form, "Tiêu đề")
        self.doc_title.delete(0, "end")
        self.doc_title.insert(0, "Báo giá dịch vụ")
        ttk.Button(form, text="Tạo báo giá / hóa đơn", command=self._add_document).pack(side="left", padx=5)
        ttk.Label(
            self.document_tab,
            text="Tạo tài liệu sẽ tính giá tại máy chủ theo bảng giá sản phẩm của bạn.",
        ).pack(anchor="w", pady=(0, 8))
        status_row = ttk.Frame(self.document_tab)
        status_row.pack(fill="x", pady=(0, 8))
        ttk.Label(status_row, text="Cập nhật trạng thái đã chọn:").pack(side="left", padx=5)
        self.doc_status = ttk.Combobox(
            status_row,
            values=("sent", "accepted", "paid"),
            state="readonly",
            width=12,
        )
        self.doc_status.set("sent")
        self.doc_status.pack(side="left", padx=5)
        ttk.Button(status_row, text="Cập nhật", command=self._update_document_status).pack(side="left", padx=5)
        self.document_tree = self._tree(
            self.document_tab,
            ("id", "number", "type", "title", "customer", "status", "total"),
            ("ID", "Mã", "Loại", "Tiêu đề", "Khách hàng", "Trạng thái", "Tổng (₫)"),
        )

    @staticmethod
    def _entry(parent: ttk.Frame, placeholder: str) -> PlaceholderEntry:
        entry = PlaceholderEntry(parent, placeholder)
        entry.pack(side="left", padx=5)
        return entry

    @staticmethod
    def _entry_value(entry: PlaceholderEntry) -> str:
        return entry.value()

    @staticmethod
    def _tree(parent: ttk.Frame, columns: tuple[str, ...], headings: tuple[str, ...]) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading)
            tree.column(column, width=130, minwidth=70)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return tree

    @staticmethod
    def _clear(tree: ttk.Treeview) -> None:
        tree.delete(*tree.get_children())

    def _run(self, action: Any) -> None:
        try:
            action()
        except (RuntimeError, ValueError, KeyError, json.JSONDecodeError) as error:
            messagebox.showerror("Thao tác không thành công", str(error))

    def _add_customer(self) -> None:
        name = self._entry_value(self.customer_name)
        if not name:
            messagebox.showerror("Thiếu dữ liệu", "Hãy nhập tên khách hàng.")
            return
        def save() -> None:
            self.api.request(
                "POST",
                "/api/customers",
                {
                    "name": name,
                    "company": self._entry_value(self.customer_company),
                    "email": self._entry_value(self.customer_email),
                },
            )
            self.refresh_customers()
            for field in (self.customer_name, self.customer_company, self.customer_email):
                field.reset()
        self._run(save)

    def _add_product(self) -> None:
        try:
            unit_price = float(self._entry_value(self.product_price))
            if unit_price <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Đơn giá không hợp lệ", "Nhập đơn giá lớn hơn 0.")
            return
        def save() -> None:
            self.api.request(
                "POST",
                "/api/products",
                {
                    "name": self._entry_value(self.product_name),
                    "unit_price": unit_price,
                    "unit": self._entry_value(self.product_unit) or "lần",
                },
            )
            self.refresh_products()
            for field in (self.product_name, self.product_price, self.product_unit):
                field.reset()
        self._run(save)

    def _add_document(self) -> None:
        try:
            customer_id = int(self._entry_value(self.doc_customer_id))
            product_id = int(self._entry_value(self.doc_product_id))
            quantity = float(self._entry_value(self.doc_quantity))
            if quantity <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Thiếu dữ liệu", "Nhập ID khách hàng, ID sản phẩm và số lượng hợp lệ.")
            return
        def save() -> None:
            result = self.api.request(
                "POST",
                "/api/documents",
                {
                    "kind": self.doc_kind.get(),
                    "customer_id": customer_id,
                    "title": self._entry_value(self.doc_title) or "Tài liệu dịch vụ",
                    "items": [{"product_id": product_id, "quantity": quantity}],
                    "discount_percent": 0,
                    "tax_percent": 0,
                },
            )
            messagebox.showinfo("Đã tạo tài liệu", f"Mã {result['number']} · Tổng {result['total']} ₫")
            self.refresh_documents()
        self._run(save)

    def _update_document_status(self) -> None:
        selected = self.document_tree.selection()
        if not selected:
            messagebox.showerror("Chưa chọn tài liệu", "Chọn một tài liệu trong danh sách trước.")
            return
        document_id = self.document_tree.item(selected[0], "values")[0]
        self._run(
            lambda: (
                self.api.request(
                    "PATCH",
                    f"/api/documents/{document_id}/status",
                    {"status": self.doc_status.get()},
                ),
                self.refresh_documents(),
            )
        )

    def refresh_all(self) -> None:
        self.refresh_customers()
        self.refresh_products()
        self.refresh_documents()

    def refresh_customers(self) -> None:
        rows = self.api.request("GET", "/api/customers")
        self._clear(self.customer_tree)
        for row in rows:
            self.customer_tree.insert("", "end", values=(row["id"], row["name"], row["company"], row["email"]))

    def refresh_products(self) -> None:
        rows = self.api.request("GET", "/api/products")
        self._clear(self.product_tree)
        for row in rows:
            self.product_tree.insert("", "end", values=(row["id"], row["name"], row["unit"], row["unit_price"]))

    def refresh_documents(self) -> None:
        rows = self.api.request("GET", "/api/documents")
        self._clear(self.document_tree)
        for row in rows:
            self.document_tree.insert(
                "",
                "end",
                values=(row["id"], row["number"], row["type"], row["title"], row["customer"], row["status"], row["total"]),
            )


def main() -> None:
    root = tk.Tk()
    VinhDesktopApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
