(function () {
  "use strict";

  function initCountdown() {
    const el = document.getElementById("pending-banner");
    const cd = document.getElementById("countdown");
    if (!el || !cd) return;
    const expires = parseFloat(el.dataset.expires) * 1000;
    function tick() {
      const left = Math.max(0, Math.ceil((expires - Date.now()) / 1000));
      cd.textContent = String(left);
      if (left <= 0) location.reload();
      else setTimeout(tick, 1000);
    }
    tick();
  }

  function submitMove(fromNumber, toNumber) {
    if (fromNumber === toNumber) return;
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

  function clearDropMarkers(list) {
    list.querySelectorAll(".rule-row").forEach((row) => {
      row.classList.remove("drop-before", "drop-after");
    });
  }

  function initRuleDrag() {
    const list = document.getElementById("rule-list");
    if (!list || list.dataset.locked === "1") return;

    let dragEl = null;

    list.querySelectorAll(".rule-row[draggable='true']").forEach((row) => {
      row.addEventListener("dragstart", (ev) => {
        dragEl = row;
        row.classList.add("is-dragging");
        ev.dataTransfer.effectAllowed = "move";
        ev.dataTransfer.setData("text/plain", row.dataset.number || "");
        // Improve ghost opacity in some browsers
        try {
          ev.dataTransfer.setDragImage(row, 24, 24);
        } catch (_) {
          /* ignore */
        }
      });

      row.addEventListener("dragend", () => {
        row.classList.remove("is-dragging");
        clearDropMarkers(list);
        dragEl = null;
      });

      row.addEventListener("dragover", (ev) => {
        if (!dragEl || dragEl === row) return;
        ev.preventDefault();
        ev.dataTransfer.dropEffect = "move";
        const rect = row.getBoundingClientRect();
        const before = ev.clientY < rect.top + rect.height / 2;
        clearDropMarkers(list);
        row.classList.add(before ? "drop-before" : "drop-after");
      });

      row.addEventListener("dragleave", () => {
        row.classList.remove("drop-before", "drop-after");
      });

      row.addEventListener("drop", (ev) => {
        ev.preventDefault();
        if (!dragEl || dragEl === row) return;
        const rows = Array.from(list.querySelectorAll(".rule-row[data-number]"));
        const fromIdx = rows.indexOf(dragEl);
        const overIdx = rows.indexOf(row);
        if (fromIdx < 0 || overIdx < 0) return;
        const rect = row.getBoundingClientRect();
        const before = ev.clientY < rect.top + rect.height / 2;
        let insertIdx = before ? overIdx : overIdx + 1;
        if (fromIdx < insertIdx) insertIdx -= 1;
        const from = parseInt(dragEl.dataset.number || "", 10);
        const to = insertIdx + 1;
        clearDropMarkers(list);
        if (!from || to < 1 || to === from) return;
        submitMove(from, to);
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initCountdown();
    initRuleDrag();
  });
})();
