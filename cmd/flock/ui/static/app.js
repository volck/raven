// Live indicator: subscribes to /ws, flashes on every frame.
// On engine/secret pages, soft-reloads when a matching engine emits.
(function () {
  const dot = document.getElementById("live");
  if (!dot) return;
  let ws, backoff = 1000, reloadTimer = null;

  function currentEngine() {
    const m = location.pathname.match(/^\/ui\/engines\/([^/]+)/);
    return m ? decodeURIComponent(m[1]) : null;
  }

  function scheduleReload() {
    if (reloadTimer) return;
    reloadTimer = setTimeout(() => location.reload(), 3000);
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(proto + "//" + location.host + "/ws");
    ws.onopen = () => {
      dot.classList.add("on");
      dot.title = "live";
      backoff = 1000;
    };
    ws.onmessage = (e) => {
      dot.classList.add("flash");
      setTimeout(() => dot.classList.remove("flash"), 200);
      try {
        const msg = JSON.parse(e.data);
        const eng = currentEngine();
        if (eng && msg.engine === eng) scheduleReload();
      } catch (_) {}
    };
    ws.onclose = () => {
      dot.classList.remove("on");
      dot.title = "reconnecting…";
      setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 30000);
    };
    ws.onerror = () => { try { ws.close(); } catch (_) {} };
  }
  connect();
})();

function filterRows(q) {
  q = q.toLowerCase();
  const tbody = document.querySelector("#secrets tbody");
  if (!tbody) return;
  for (const row of tbody.rows) {
    row.style.display = row.cells[0].innerText.toLowerCase().includes(q) ? "" : "none";
  }
}

// Tab switcher: click a .tab to activate the matching .tab-panel.
(function () {
  const tabs = document.querySelectorAll(".tab");
  if (!tabs.length) return;
  function activate(name) {
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.dataset.panel === name));
    if (history.replaceState) history.replaceState(null, "", "#" + name);
  }
  tabs.forEach(t => t.addEventListener("click", () => activate(t.dataset.tab)));
  const initial = location.hash.replace("#", "");
  if (initial && document.querySelector('.tab[data-tab="' + CSS.escape(initial) + '"]')) {
    activate(initial);
  }
})();
