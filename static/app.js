document.addEventListener("click", (event) => {
  const addButton = event.target.closest("#add-item");
  if (addButton) {
    const template = document.querySelector("#item-template");
    const rows = document.querySelector("#item-rows");
    if (template && rows) rows.append(template.content.cloneNode(true));
  }

  const removeButton = event.target.closest(".remove-item");
  if (removeButton) {
    const rows = document.querySelector("#item-rows");
    const row = removeButton.closest(".item-row");
    if (rows && row && rows.querySelectorAll(".item-row").length > 1) row.remove();
  }
});

document.addEventListener("change", (event) => {
  if (event.target.matches('select[name="kind"]')) {
    const title = document.querySelector('input[name="title"]');
    if (title) title.value = event.target.value === "invoice" ? "Hóa đơn dịch vụ" : "Báo giá dịch vụ";
  }
});
