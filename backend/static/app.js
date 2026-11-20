(function () {
  "use strict";

  const REFRESH_MS = 45000;
  let sorting = false; // true while a drag (mouse or touch) is in progress

  /* ---------- Confirm-or-rollback countdown ---------- */
  function initCountdown() {
    const el = document.getElementById("pending-banner");
    const cd = document.getElementById("countdown");
    if (!el || !cd) return;
    const fill = document.getElementById("countdown-fill");
    const expires = parseFloat(el.dataset.expires) * 1000;
    const total = Math.max(1, parseFloat(el.dataset.total || "60"));
    function tick() {
      const left = Math.max(0, Math.ceil((expires - Date.now()) / 1000));
      cd.textContent = String(left);
      if (fill) fill.style.transform = "scaleX(" + Math.min(1, left / total) + ")";
      if (left <= 0) location.reload();
      else setTimeout(tick, 1000);
    }
    tick();
  }

  /* ---------- Rule reorder ---------- */
  function submitMove(fromNumber, toNumber) {
    if (!fromNumber || !toNumber || fromNumber === toNumber) return;
    const form = document.createElement("form");
    form.method = "POST";
    form.action = "/actions/move/" + encodeURIComponent(String(fromNumber));
    form.style.display = "none";
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "to_number";
    input.value = String(toNumber);
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
  }

  function rowsOf(list) {
    return Array.from(list.querySelectorAll(".rule-row[data-number]"));
  }

  function clearMarkers(list) {
    list.querySelectorAll(".drop-before, .drop-after").forEach((row) => {
      row.classList.remove("drop-before", "drop-after");
    });
  }

  // Given the row under the pointer, mark the drop position and return target number.
  function markDrop(list, dragRow, overRow, clientY) {
    clearMarkers(list);
    if (!overRow || overRow === dragRow) return null;
    const rows = rowsOf(list);
    const fromIdx = rows.indexOf(dragRow);
    const overIdx = rows.indexOf(overRow);
    if (fromIdx < 0 || overIdx < 0) return null;
    const rect = overRow.getBoundingClientRect();
    const before = clientY < rect.top + rect.height / 2;
    let insertIdx = before ? overIdx : overIdx + 1;
    if (fromIdx < insertIdx) insertIdx -= 1;
    if (insertIdx === fromIdx) return null; // dropping in place: no marker
    overRow.classList.add(before ? "drop-before" : "drop-after");
    return insertIdx + 1;
  }

  function startSort(list, row) {
    sorting = true;
    list.classList.add("is-sorting");
    row.classList.add("is-dragging");
  }

  function endSort(list, row) {
    sorting = false;
    list.classList.remove("is-sorting");
    if (row) row.classList.remove("is-dragging");
    clearMarkers(list);
  }

  function initRuleDrag() {
    const list = document.getElementById("rule-list");
    if (!list || list.dataset.locked === "1" || list.dataset.bound === "1") return;
    list.dataset.bound = "1";

    let dragRow = null;
    let target = null;

    // Mouse / native HTML5 DnD — only the handle is draggable.
    list.querySelectorAll(".drag-handle[draggable='true']").forEach((handle) => {
      const row = handle.closest(".rule-row");

      handle.addEventListener("dragstart", (ev) => {
        dragRow = row;
        target = null;
        ev.dataTransfer.effectAllowed = "move";
        ev.dataTransfer.setData("text/plain", row.dataset.number || "");
        try {
          ev.dataTransfer.setDragImage(row, 20, row.offsetHeight / 2);
        } catch (_) { /* ignore */ }
        requestAnimationFrame(() => startSort(list, row));
      });

      handle.addEventListener("dragend", () => {
        endSort(list, dragRow);
        dragRow = null;
      });

      // Keyboard: arrow keys move one step.
      handle.addEventListener("keydown", (ev) => {
        const n = parseInt(row.dataset.number || "", 10);
        const max = rowsOf(list).length;
        if (ev.key === "ArrowUp" && n > 1) {
          ev.preventDefault();
          submitMove(n, n - 1);
        } else if (ev.key === "ArrowDown" && n < max) {
          ev.preventDefault();
          submitMove(n, n + 1);
        }
      });

      // Touch / pen: pointer-driven drag, since HTML5 DnD is unreliable on mobile.
      handle.addEventListener("pointerdown", (ev) => {
        if (ev.pointerType === "mouse") return;
        ev.preventDefault();
        handle.setPointerCapture(ev.pointerId);
        dragRow = row;
        target = null;
        startSort(list, row);

        const move = (e) => {
          const el = document.elementFromPoint(e.clientX, e.clientY);
          const over = el && el.closest ? el.closest(".rule-row") : null;
          target = over && list.contains(over) ? markDrop(list, row, over, e.clientY) : null;
          if (!target) clearMarkers(list);
          // Nudge-scroll near viewport edges.
          if (e.clientY < 70) window.scrollBy(0, -12);
          else if (e.clientY > window.innerHeight - 70) window.scrollBy(0, 12);
        };
        const up = () => {
          handle.removeEventListener("pointermove", move);
          handle.removeEventListener("pointerup", up);
          handle.removeEventListener("pointercancel", cancel);
          const from = parseInt(row.dataset.number || "", 10);
          const to = target;
          endSort(list, row);
          dragRow = null;
          if (to) submitMove(from, to);
        };
        const cancel = () => {
          handle.removeEventListener("pointermove", move);
          handle.removeEventListener("pointerup", up);
          handle.removeEventListener("pointercancel", cancel);
          endSort(list, row);
          dragRow = null;
        };
        handle.addEventListener("pointermove", move);
        handle.addEventListener("pointerup", up);
        handle.addEventListener("pointercancel", cancel);
      });
    });

    // Drop targets: whole rows, delegated on the list.
    list.addEventListener("dragover", (ev) => {
      if (!dragRow) return;
      const over = ev.target.closest(".rule-row");
      if (!over) return;
      ev.preventDefault();
      ev.dataTransfer.dropEffect = "move";
      target = markDrop(list, dragRow, over, ev.clientY);
    });

    list.addEventListener("dragleave", (ev) => {
      if (!list.contains(ev.relatedTarget)) {
        clearMarkers(list);
        target = null;
      }
    });

    list.addEventListener("drop", (ev) => {
      if (!dragRow) return;
      ev.preventDefault();
      const from = parseInt(dragRow.dataset.number || "", 10);
      const to = target;
      endSort(list, dragRow);
      dragRow = null;
      if (to) submitMove(from, to);
    });
  }

  /* ---------- Idle partial refresh ---------- */
  const live = { last: Date.now() };

  function setLiveText() {
    const wrap = document.getElementById("live");
    const text = document.getElementById("live-text");
    if (!wrap || !text) return;
    const secs = Math.round((Date.now() - live.last) / 1000);
    text.textContent = secs < 10 ? "Updated now" : "Updated " + (secs < 60 ? secs + "s" : Math.round(secs / 60) + " min") + " ago";
    wrap.classList.toggle("is-stale", secs > REFRESH_MS / 1000 * 2.5);
  }

  function canRefresh() {
    if (document.hidden || sorting) return false;
    if (document.body.dataset.page !== "dashboard") return false;
    if (document.getElementById("pending-banner")) return false; // countdown owns reloads
    const active = document.activeElement;
    if (active && active.closest && active.closest("form") && /^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName)) {
      return false; // someone is typing or choosing
    }
    return true;
  }

  async function refresh() {
    if (!canRefresh()) return;
    let html;
    try {
      const res = await fetch("/", { credentials: "same-origin", headers: { "X-Partial": "1" } });
      if (res.redirected || res.status === 401) { location.href = "/login"; return; }
      if (!res.ok) return;
      html = await res.text();
    } catch (_) {
      return; // network blip; keep the current view and show it ageing
    }
    if (!canRefresh()) return;
    const doc = new DOMParser().parseFromString(html, "text/html");
    if (doc.getElementById("pending-banner")) { location.reload(); return; }

    document.querySelectorAll("[data-live]").forEach((el) => {
      const fresh = doc.querySelector('[data-live="' + el.dataset.live + '"]');
      if (!fresh) return;
      if (el.contains(document.activeElement) && document.activeElement !== document.body) return;
      if (el.innerHTML !== fresh.innerHTML) el.replaceWith(fresh);
    });
    // Hero line and active state can change too (e.g. policy changed elsewhere).
    ["hero"].forEach((cls) => {
      const cur = document.querySelector("." + cls);
      const fresh = doc.querySelector("." + cls);
      if (cur && fresh && cur.innerHTML !== fresh.innerHTML) cur.replaceWith(fresh);
    });

    initRuleDrag();
    live.last = Date.now();
    const wrap = document.getElementById("live");
    if (wrap) {
      wrap.classList.remove("is-flash");
      void wrap.offsetWidth;
      wrap.classList.add("is-flash");
    }
    setLiveText();
  }

  function initLive() {
    if (document.body.dataset.page !== "dashboard") {
      const wrap = document.getElementById("live");
      if (wrap) wrap.hidden = true;
      return;
    }
    setInterval(refresh, REFRESH_MS);
    setInterval(setLiveText, 5000);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && Date.now() - live.last > REFRESH_MS) refresh();
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initCountdown();
    initRuleDrag();
    initLive();
  });
})();
