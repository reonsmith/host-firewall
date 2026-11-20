/* Host Firewall static demo (GitHub Pages).
 *
 * The page is the real dashboard rendered in demo mode. This script stands in
 * for the server: form posts and links are handled in the browser, changes are
 * applied to the page, and the confirm-or-rollback window works as in the app.
 * Nothing is saved; reloading resets everything.
 */
(function () {
  "use strict";

  const CONFIRM_SECONDS = 60;
  const UP = "↑";
  const DOWN = "↓";
  const ARROW = "→";
  let pending = null; // { desc, snapshot, timer, expires }

  /* ---------- styles only the static demo needs ---------- */
  const style = document.createElement("style");
  style.textContent = `
    .static-banner { display:flex; justify-content:space-between; align-items:center; gap:.5rem 1rem; flex-wrap:wrap;
      padding:.7rem .9rem .7rem 1.1rem; margin-bottom:1.1rem; border-radius:var(--r-row);
      background:var(--panel); border:1px solid var(--line-strong); color:var(--muted); font-size:.88rem; }
    .static-banner strong { color:var(--lime); font-weight:600; }
    body.demo-pending #pending-banner { position:sticky; top:72px; z-index:15; box-shadow:0 12px 30px rgba(0,0,0,.45); }
    body.demo-pending .rule-actions, body.demo-pending .drag-handle,
    body.demo-pending #add form, body.demo-pending .policy-controls { opacity:.4; pointer-events:none; }
    .demo-toast { position:fixed; left:50%; bottom:24px; transform:translateX(-50%); z-index:50; max-width:min(92vw,560px);
      padding:.7rem 1rem; border-radius:12px; background:var(--text); color:var(--bg); font-size:.88rem;
      box-shadow:0 12px 30px rgba(0,0,0,.45); }
    .rule-row.is-new { border-color: var(--lime); }
  `;
  document.head.appendChild(style);

  /* ---------- helpers ---------- */
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const list = () => document.getElementById("rule-list");
  const rows = () => $$(".rule-row[data-number]", list());
  const addForm = () => $("#add form");

  let toastTimer = null;
  function toast(message) {
    let el = $(".demo-toast");
    if (!el) {
      el = document.createElement("div");
      el.className = "demo-toast";
      el.setAttribute("role", "status");
      document.body.appendChild(el);
    }
    el.textContent = message;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3800);
  }

  function now() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  /* ---------- rules ---------- */
  function actionsHtml(n, last) {
    const spacer = '<span class="spacer" aria-hidden="true"></span>';
    const up = n > 1
      ? `<form method="post" action="/actions/move/${n}"><input type="hidden" name="to_number" value="${n - 1}" /><button type="submit" class="ghost icon" aria-label="Move rule ${n} up">${UP}</button></form>`
      : spacer;
    const down = !last
      ? `<form method="post" action="/actions/move/${n}"><input type="hidden" name="to_number" value="${n + 1}" /><button type="submit" class="ghost icon" aria-label="Move rule ${n} down">${DOWN}</button></form>`
      : spacer;
    return `<span class="move-slot">${up}${down}</span>` +
      `<a class="ghost-link" href="/edit/${n}" aria-label="Edit rule ${n}">Edit</a>` +
      `<form method="post" action="/actions/delete/${n}" onsubmit="return confirm('Delete rule ${n}? This opens the confirm window.');">` +
      `<button type="submit" class="ghost danger" aria-label="Delete rule ${n}">Delete</button></form>`;
  }

  function refreshRules() {
    const all = rows();
    all.forEach((row, i) => {
      const n = i + 1;
      row.dataset.number = String(n);
      $(".rule-num", row).textContent = "#" + n;
      $(".drag-handle", row).setAttribute("aria-label", `Reorder rule ${n}. Drag, or press arrow up or down.`);
      $(".rule-actions", row).innerHTML = actionsHtml(n, i === all.length - 1);
    });
    const count = $("#rules .count");
    if (count) count.textContent = `${all.length} rule${all.length === 1 ? "" : "s"}`;
    const allow = $$(".rule-primary .badge.action-allow, .rule-primary .badge.action-limit", list()).length;
    const kpi = $('.kpi[href="#rules"]');
    if (kpi) {
      $(".kpi-value", kpi).textContent = String(all.length);
      $(".kpi-chip", kpi).textContent = `${allow} allow, ${all.length - allow} block`;
    }
    // Re-bind drag on a fresh copy of the list so no listeners are doubled.
    const old = list();
    const fresh = old.cloneNode(true);
    fresh.removeAttribute("data-bound");
    old.replaceWith(fresh);
    if (window.HostFirewall) window.HostFirewall.initRuleDrag();
  }

  function ruleData(row) {
    return {
      to: $(".rule-to", row).textContent.trim(),
      action: $(".rule-primary .badge", row).textContent.trim(),
      direction: $(".rule-dir", row).textContent.trim(),
      from: $(".rule-from", row).textContent.replace(/^\s*from\s*/, "").trim(),
      comment: ($(".rule-comment", row) || { textContent: "" }).textContent.trim(),
    };
  }

  function fillRow(row, d) {
    row.classList.remove("drop-before", "drop-after", "is-dragging");
    $(".rule-to", row).textContent = d.to;
    const badge = $(".rule-primary .badge", row);
    badge.className = "badge action-" + d.action;
    badge.textContent = d.action;
    $(".rule-dir", row).textContent = d.direction;
    $(".rule-from", row).innerHTML = `<span class="muted">from</span> ${esc(d.from)}`;
    const fam = $(".rule-primary .badge[class*='family-']", row);
    const family = /:|\(v6\)/.test(d.from + d.to) ? "ipv6" : "ipv4";
    fam.className = "badge family-" + family;
    fam.textContent = family;
    let comment = $(".rule-comment", row);
    if (d.comment) {
      if (!comment) {
        comment = document.createElement("div");
        comment.className = "rule-comment";
        $(".rule-body", row).appendChild(comment);
      }
      comment.textContent = d.comment;
      comment.title = d.comment;
    } else if (comment) {
      comment.remove();
    }
  }

  /* ---------- confirm-or-rollback ---------- */
  function snapshot() {
    return $("main").innerHTML.replace(/ data-bound="1"/g, "");
  }

  function mutate(desc, apply) {
    if (pending) {
      toast("Confirm or roll back the pending change first.");
      return;
    }
    const snap = snapshot();
    apply();
    pending = { desc, snapshot: snap, expires: Date.now() + CONFIRM_SECONDS * 1000 };
    showBanner(desc);
  }

  function showBanner(desc) {
    const banner = document.createElement("section");
    banner.className = "banner";
    banner.id = "pending-banner";
    banner.setAttribute("role", "status");
    banner.setAttribute("aria-live", "polite");
    banner.innerHTML =
      `<div class="banner-body"><strong>Pending change.</strong> Confirm within ` +
      `<span id="countdown">${CONFIRM_SECONDS}</span>s or it rolls back.` +
      `<div class="muted">${esc(desc)}</div>` +
      `<div class="countdown-track" aria-hidden="true"><div class="countdown-fill" id="countdown-fill"></div></div></div>` +
      `<div class="row"><form method="post" action="/actions/confirm"><button type="submit">Confirm</button></form>` +
      `<form method="post" action="/actions/rollback"><button type="submit" class="danger">Roll back now</button></form></div>`;
    const anchor = $(".static-banner");
    if (anchor) anchor.after(banner);
    else $("main").prepend(banner);
    document.body.classList.add("demo-pending");
    tick();
    pending.timer = setInterval(tick, 1000);
  }

  function tick() {
    if (!pending) return;
    const left = Math.max(0, Math.ceil((pending.expires - Date.now()) / 1000));
    const cd = document.getElementById("countdown");
    const fill = document.getElementById("countdown-fill");
    if (cd) cd.textContent = String(left);
    if (fill) fill.style.transform = `scaleX(${left / CONFIRM_SECONDS})`;
    if (left <= 0) rollback(true);
  }

  function finish(outcome) {
    clearInterval(pending.timer);
    const desc = pending.desc;
    pending = null;
    document.body.classList.remove("demo-pending");
    addHistory(desc, outcome);
  }

  function confirmChange() {
    const banner = document.getElementById("pending-banner");
    if (banner) banner.remove();
    finish("confirmed");
    toast("Confirmed. In the real app the change stays in place.");
  }

  function rollback(timedOut) {
    $("main").innerHTML = pending.snapshot;
    if (window.HostFirewall) window.HostFirewall.initRuleDrag();
    finish("rolled_back");
    toast(timedOut
      ? "Time ran out, so the change rolled back on its own. That's what saves you if a rule locks you out."
      : "Rolled back. The previous rules are restored.");
  }

  function addHistory(desc, outcome) {
    const tbody = $("#history tbody");
    if (tbody) {
      const tr = document.createElement("tr");
      const ok = outcome === "confirmed";
      tr.innerHTML = `<td class="when">${now()}</td><td><span class="badge ${ok ? "ok" : "bad"}">${outcome.replace("_", " ")}</span></td><td>${esc(desc)}</td>`;
      tbody.prepend(tr);
    }
    const kpi = $('.kpi[href="#history"]');
    if (kpi) {
      $(".kpi-value", kpi).textContent = "just now";
      const chip = $(".kpi-chip", kpi);
      chip.textContent = outcome.replace("_", " ");
      chip.title = desc;
    }
  }

  /* ---------- the add / edit form ---------- */
  function setField(form, name, value) {
    const el = form.elements.namedItem(name);
    if (el && value != null) el.value = value;
  }

  function prefill(params) {
    const form = addForm();
    if (!form) return;
    exitEdit();
    ["action", "direction", "port_or_app", "from_address", "comment"].forEach((k) => {
      if (params.has(k)) setField(form, k, params.get(k));
    });
    $("#add").scrollIntoView({ behavior: "smooth", block: "start" });
    form.elements.namedItem("port_or_app").focus({ preventScroll: true });
  }

  function enterEdit(n) {
    const form = addForm();
    const row = rows()[n - 1];
    if (!form || !row) return;
    const d = ruleData(row);
    setField(form, "action", d.action);
    setField(form, "direction", d.direction);
    setField(form, "port_or_app", d.to.replace(" (v6)", ""));
    setField(form, "from_address", d.from.replace(" (v6)", ""));
    setField(form, "comment", d.comment);
    setField(form, "insert_at", "");
    form.dataset.editing = String(n);
    $("#add h2").textContent = `Edit rule #${n}`;
    $('button[type="submit"]', form).textContent = "Save rule";
    if (!$(".demo-cancel", form)) {
      const cancel = document.createElement("a");
      cancel.className = "ghost-link demo-cancel";
      cancel.href = "/";
      cancel.textContent = "Cancel";
      $('button[type="submit"]', form).after(cancel);
    }
    $("#add").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function exitEdit() {
    const form = addForm();
    if (!form || !form.dataset.editing) return;
    delete form.dataset.editing;
    $("#add h2").textContent = "Add rule";
    $('button[type="submit"]', form).textContent = "Add rule";
    const cancel = $(".demo-cancel", form);
    if (cancel) cancel.remove();
    form.reset();
  }

  /* ---------- route form posts ---------- */
  function handle(form) {
    const url = new URL(form.getAttribute("action") || "", location.href);
    const path = url.pathname;
    if (!path.startsWith("/actions/") && path !== "/login") return false;
    const fd = new FormData(form);
    const get = (k) => String(fd.get(k) || "").trim();
    let m;

    if (path === "/actions/confirm") { if (pending) confirmChange(); return true; }
    if (path === "/actions/rollback") { if (pending) rollback(false); return true; }
    if (path === "/actions/logout") { toast("Signing out is turned off in the demo."); return true; }
    if (path === "/actions/restore") { toast("Snapshots are taken before each change in the real app."); return true; }

    if ((m = path.match(/^\/actions\/move\/(\d+)$/))) {
      const from = +m[1];
      const to = +get("to_number");
      if (!to || to === from) return true;
      mutate(`move rule ${from} ${ARROW} ${to}`, () => {
        const el = rows()[from - 1];
        el.remove();
        const rest = rows();
        if (to - 1 >= rest.length) list().appendChild(el);
        else list().insertBefore(el, rest[to - 1]);
        refreshRules();
      });
      return true;
    }

    if ((m = path.match(/^\/actions\/delete\/(\d+)$/))) {
      const n = +m[1];
      mutate(`delete rule ${n}`, () => { rows()[n - 1].remove(); refreshRules(); });
      return true;
    }

    if (path === "/actions/add") {
      const d = {
        action: get("action") || "allow",
        direction: get("direction") || "in",
        to: get("port_or_app"),
        from: get("from_address") || "Anywhere",
        comment: get("comment"),
      };
      const editing = +(form.dataset.editing || 0);
      if (editing) {
        mutate(`edit #${editing} ${ARROW} ${d.action} ${d.to} from ${d.from}`, () => {
          fillRow(rows()[editing - 1], d);
          refreshRules();
          exitEdit();
        });
        return true;
      }
      const at = +get("insert_at");
      mutate(`add ${d.action} ${d.to} from ${d.from}${d.comment ? ` (${d.comment})` : ""}`, () => {
        const row = rows()[0].cloneNode(true);
        fillRow(row, d);
        row.classList.add("is-new");
        const all = rows();
        if (at >= 1 && at <= all.length) list().insertBefore(row, all[at - 1]);
        else list().appendChild(row);
        refreshRules();
        form.reset();
        const added = $(".rule-row.is-new", list());
        if (added) added.scrollIntoView({ behavior: "smooth", block: "center" });
      });
      return true;
    }

    if (path === "/actions/default") {
      const dir = get("direction");
      const pol = get("policy");
      mutate(`default ${pol} (${dir})`, () => {
        const idx = { incoming: 0, outgoing: 1, routed: 2 }[dir];
        const dd = $$(".policy-item dd")[idx];
        if (dd) { dd.textContent = pol; dd.className = "pol-" + pol; }
        const strong = $$(".hero-sub strong")[idx];
        if (strong) { strong.textContent = pol; strong.className = "pol-" + pol; }
      });
      return true;
    }

    if (path === "/actions/logging") {
      const level = get("level");
      mutate(`logging ${level}`, () => {
        const dd = $$(".policy-item dd")[3];
        if (dd) dd.textContent = level;
        const strong = $$(".hero-sub strong")[3];
        if (strong) strong.textContent = level;
      });
      return true;
    }

    if (path === "/actions/disable" || path === "/actions/enable") {
      const enable = path.endsWith("enable");
      mutate(enable ? "enable UFW" : "disable UFW", () => {
        const state = $(".state");
        state.className = "state " + (enable ? "on" : "off");
        state.textContent = enable ? "Active" : "Inactive";
        form.setAttribute("action", enable ? "/actions/disable" : "/actions/enable");
        const btn = $("button", form);
        btn.textContent = enable ? "Disable UFW" : "Enable UFW";
        btn.className = enable ? "ghost danger" : "ghost";
      });
      return true;
    }

    toast("That action isn't part of the demo.");
    return true;
  }

  // app.js reorders rules by building a hidden form and calling form.submit(),
  // which doesn't fire a submit event, so intercept that too.
  const nativeSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () {
    if (!handle(this)) nativeSubmit.call(this);
    if (this.style.display === "none") this.remove();
  };

  // Bubble phase, so inline onsubmit="return confirm(...)" runs first.
  document.addEventListener("submit", (ev) => {
    if (ev.defaultPrevented) return;
    if (handle(ev.target)) ev.preventDefault();
  });

  document.addEventListener("click", (ev) => {
    const a = ev.target.closest && ev.target.closest("a[href]");
    if (!a) return;
    const href = a.getAttribute("href");
    let m;
    if ((m = href.match(/^\/edit\/(\d+)$/))) { ev.preventDefault(); if (!pending) enterEdit(+m[1]); return; }
    if (href === "/export") { ev.preventDefault(); toast("In the real app this downloads /etc/ufw as a .tar.gz."); return; }
    if (href === "/") { ev.preventDefault(); exitEdit(); return; }
    if (href.startsWith("/?")) { ev.preventDefault(); prefill(new URLSearchParams(href.slice(2).split("#")[0])); }
  });
})();
