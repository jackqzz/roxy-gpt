/* roxy-accounts 共享 UI: SVG 图标库 + 侧边栏渲染 */
(function () {
  "use strict";

  const P = {
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    crown: '<path d="M11.56 3.27a.5.5 0 0 1 .88 0l2.95 5.6a1 1 0 0 0 1.52.3l4.27-3.67a.5.5 0 0 1 .8.52l-2.84 10.25a1 1 0 0 1-.95.73H5.81a1 1 0 0 1-.96-.73L2.02 6.02a.5.5 0 0 1 .8-.52l4.27 3.66a1 1 0 0 0 1.52-.29z"/><path d="M5 21h14"/>',
    settings: '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    "app-window": '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M10 4v4"/><path d="M2 8h20"/><path d="M6 4v4"/>',
    "layout-grid": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
    "shield-check": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1 1 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    "user-plus": '<path d="M2 21a8 8 0 0 1 13.29-6"/><circle cx="10" cy="8" r="5"/><path d="M19 16v6"/><path d="M22 19h-6"/>',
    "log-out": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>',
    "refresh-cw": '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
    key: '<path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
    "cloud-upload": '<path d="M4 14.9A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.24"/><path d="M12 12v9"/><path d="m16 16-4-4-4 4"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>',
    "trash-2": '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/>',
    square: '<rect x="7" y="7" width="10" height="10" rx="1.5"/>',
    plus: '<path d="M5 12h14"/><path d="M12 5v14"/>',
    mail: '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
    send: '<path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>',
    x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    sparkle: '<path d="m12 3 1.9 5.8a2 2 0 0 0 1.3 1.3L21 12l-5.8 1.9a2 2 0 0 0-1.3 1.3L12 21l-1.9-5.8a2 2 0 0 0-1.3-1.3L3 12l5.8-1.9a2 2 0 0 0 1.3-1.3Z"/><path d="M19 3v4"/><path d="M21 5h-4"/>',
    hash: '<line x1="4" x2="20" y1="9" y2="9"/><line x1="4" x2="20" y1="15" y2="15"/><line x1="10" x2="8" y1="3" y2="21"/><line x1="16" x2="14" y1="3" y2="21"/>',
    pencil: '<path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/>',
    clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    list: '<line x1="8" x2="21" y1="6" y2="6"/><line x1="8" x2="21" y1="12" y2="12"/><line x1="8" x2="21" y1="18" y2="18"/><line x1="3" x2="3.01" y1="6" y2="6"/><line x1="3" x2="3.01" y1="12" y2="12"/><line x1="3" x2="3.01" y1="18" y2="18"/>',
    timer: '<line x1="10" x2="14" y1="2" y2="2"/><line x1="12" x2="15" y1="14" y2="11"/><circle cx="12" cy="14" r="8"/>',
    "check-circle": '<path d="M21.8 10A10 10 0 1 1 17 3.34"/><path d="m9 11 3 3L22 4"/>',
    archive: '<rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/>',
    "rotate-ccw": '<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/>',
    smartphone: '<rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/>',
    zap: '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>'
  };

  function icon(name, cls) {
    const d = P[name];
    if (!d) return "";
    return '<svg class="ic ' + (cls || "") + '" viewBox="0 0 24 24" fill="none" '
      + 'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
      + 'stroke-linejoin="round" aria-hidden="true">' + d + "</svg>";
  }

  const NAVS = {
    gpt: [
      ["accounts", "/accounts", "users", "账号"],
      ["proxies", "/", "globe", "代理"],
      ["mothers", "/mothers", "crown", "空间母号"],
      ["settings", "/settings", "settings", "设置"]
    ],
    g: [
      ["g-accounts", "/g/accounts", "users", "G账号"],
      ["g-proxies", "/g/proxies", "globe", "代理池"],
      ["g-settings", "/g/settings", "settings", "设置"]
    ]
  };
  const PRODS = [["gpt", "/accounts", "GPT"], ["g", "/g/accounts", "Google"]];

  function renderNav() {
    const nav = document.querySelector("nav.sidebar[data-nav]");
    if (!nav) return;
    let cur = nav.dataset.nav;
    let grp = cur.indexOf("g-") === 0 ? "g" : "gpt";
    nav.innerHTML = '<div class="brand"><span class="mark">R</span>roxy-accounts</div>'
      + '<div class="prod-switch">'
      + PRODS.map(([k, href, label]) =>
          '<a href="' + href + '"' + (k === grp ? ' class="on"' : "") + ">"
          + label + "</a>").join("")
      + "</div>"
      + NAVS[grp].map(([k, href, ic, label]) =>
          '<a href="' + href + '"' + (k === cur ? ' class="on"' : "") + ">"
          + icon(ic) + "<span>" + label + "</span></a>").join("");
  }

  function hydrateIcons(root) {
    (root || document).querySelectorAll("i[data-ic]").forEach(el => {
      el.outerHTML = icon(el.dataset.ic);
    });
  }

  // ---- 页面状态持久化: [data-persist] 控件刷新后保留值 ----
  // 存 localStorage, key 按 页面路径#控件id; select 的选项还没灌进来时
  // 先把值挂 _pending, 页面灌完选项调 ui.persistReapply() 落上。
  const PKEY = "ui.persist:" + location.pathname;

  function persistLoad() {
    try { return JSON.parse(localStorage.getItem(PKEY) || "{}"); }
    catch (e) { return {}; }
  }
  function persistSave(el) {
    const all = persistLoad();
    all[el.id] = el.type === "checkbox" ? el.checked : el.value;
    try { localStorage.setItem(PKEY, JSON.stringify(all)); }
    catch (e) {}
  }
  function persistApply(el, v) {
    if (el.type === "checkbox") { el.checked = !!v; return; }
    if (el.tagName === "SELECT" &&
        ![...el.options].some(o => o.value === v)) {
      el._pendingPersist = v;          // 选项还没灌进来
      return;
    }
    el.value = v;
    el._pendingPersist = null;
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  function persistReapply() {
    document.querySelectorAll("select[data-persist]").forEach(el => {
      if (el._pendingPersist == null) return;
      const v = el._pendingPersist;
      if ([...el.options].some(o => o.value === v)) {
        el.value = v;
        el._pendingPersist = null;
        el.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  }
  function bindPersist() {
    const saved = persistLoad();
    document.querySelectorAll("[data-persist]").forEach(el => {
      if (!el.id) return;
      if (el.id in saved) persistApply(el, saved[el.id]);
      el.addEventListener("change", () => persistSave(el));
      el.addEventListener("input", () => persistSave(el));
    });
  }

  window.ui = { icon, hydrateIcons, renderNav, persistReapply };
  document.addEventListener("DOMContentLoaded", () => {
    renderNav();
    hydrateIcons();
    bindPersist();
  });
})();
