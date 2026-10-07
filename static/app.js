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

document.addEventListener("click", async (event) => {
  const toggle = event.target.closest(".password-toggle");
  if (toggle) {
    const input = toggle.parentElement.querySelector("input");
    if (!input) return;
    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(reveal));
    toggle.setAttribute("aria-label", reveal ? "Ẩn mật khẩu" : "Hiện mật khẩu");
    return;
  }

  const switchLink = event.target.closest(".auth-switch a");
  if (!switchLink || !["/login", "/register"].includes(new URL(switchLink.href).pathname)) return;
  event.preventDefault();
  await swapAuthPanel(switchLink.href);
});

async function swapAuthPanel(url, updateHistory = true) {
  const current = document.querySelector(".auth-panel");
  if (!current) {
    window.location.assign(url);
    return;
  }
  try {
    const response = await fetch(url, { headers: { "X-Requested-With": "fetch" } });
    if (!response.ok) throw new Error(`Authentication page returned ${response.status}`);
    const html = await response.text();
    const nextDocument = new DOMParser().parseFromString(html, "text/html");
    const nextPanel = nextDocument.querySelector(".auth-panel");
    if (!nextPanel) throw new Error("Authentication panel is missing");
    current.classList.add("auth-panel-leaving");
    await new Promise((resolve) => window.setTimeout(resolve, 160));
    current.replaceWith(nextPanel);
    nextPanel.classList.add("auth-panel-entering");
    window.requestAnimationFrame(() => nextPanel.classList.remove("auth-panel-entering"));
    document.title = nextDocument.title;
    if (updateHistory) window.history.pushState({}, "", url);
  } catch (error) {
    console.error("Unable to switch authentication form", error);
    window.location.assign(url);
  }
}

window.addEventListener("popstate", () => {
  if (["/login", "/register"].includes(window.location.pathname)) {
    swapAuthPanel(window.location.href, false);
  }
});
