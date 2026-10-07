const formatVnd = (value) =>
  `${Math.round(Number.isFinite(value) ? value : 0).toLocaleString("vi-VN")} ₫`;

function updateDemo(card) {
  const value = (name) => Number(card.querySelector(`[data-field="${name}"]`)?.value || 0);
  const result = card.querySelector("[data-result]");
  if (!result) return;

  if (card.dataset.demo === "vat") {
    const subtotal = value("amount");
    const tax = subtotal * value("rate") / 100;
    result.textContent = `Tiền thuế: ${formatVnd(tax)} · Tổng thanh toán: ${formatVnd(subtotal + tax)}`;
  } else if (card.dataset.demo === "quote") {
    const subtotal = value("quantity") * value("price");
    const discount = subtotal * Math.min(100, value("discount")) / 100;
    const taxable = subtotal - discount;
    const total = taxable + taxable * Math.min(100, value("tax")) / 100;
    result.textContent = `Tạm tính ${formatVnd(subtotal)} · Chiết khấu ${formatVnd(discount)} · Tổng dự toán ${formatVnd(total)}`;
  } else if (card.dataset.demo === "invoice") {
    const customer = card.querySelector('[data-field="customer"]')?.value.trim() || "Khách hàng";
    const service = card.querySelector('[data-field="service"]')?.value.trim() || "Dịch vụ";
    result.textContent = `HÓA ĐƠN MẪU\nKhách hàng: ${customer}\nNội dung: ${service}\nTổng cộng: ${formatVnd(value("amount"))}`;
  }
}

document.querySelectorAll(".demo-app-card").forEach((card) => {
  card.addEventListener("input", () => updateDemo(card));
  card.addEventListener("change", () => updateDemo(card));
  updateDemo(card);
});
