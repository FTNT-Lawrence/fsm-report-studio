(function () {
  const $ = (id) => document.getElementById(id);
  const form = $("form");
  const logEl = $("log");
  const statusEl = $("status");
  const go = $("go");
  const runState = $("runState");
  const LS_KEY = "fsm-report-studio-v1";

  function setComboHints() {
    const kind = $("kind").value;
    const version = $("version").value;
    const theme = $("theme");
    const themeHint = $("themeHint");
    const note = $("comboNote");
    const days = $("days");

    $("version").querySelector('option[value="1.3"]').disabled = kind === "ot";
    if (kind === "ot" && version === "1.3") {
      $("version").value = "1.5";
    }
    if ($("version").value === "1.3") {
      theme.value = "dark";
      theme.querySelector('option[value="light"]').disabled = true;
      themeHint.textContent = "經典 v1.3 只有深色 cyber HUD。";
    } else {
      theme.querySelector('option[value="light"]').disabled = false;
      themeHint.textContent = kind === "ot" && theme.value === "dark"
        ? "OT 深色可以產生；淺色係主要校對過嘅主題。"
        : "";
    }
    if ($("window_mode").value === "days" && !days.dataset.touched) {
      days.value = kind === "ot" ? "3" : "7";
    }
    const v = $("version").value;
    note.textContent = (kind === "ot" ? "OT／IoT v" : "SIEM v") + v +
      " · " + (theme.value === "light" ? "淺色" : "深色") +
      " · " + ($("lang").value === "zh" ? "繁中" : "EN");
  }

  $("days").addEventListener("input", () => { $("days").dataset.touched = "1"; });
  $("kind").addEventListener("change", setComboHints);
  $("version").addEventListener("change", setComboHints);
  $("theme").addEventListener("change", setComboHints);
  $("lang").addEventListener("change", setComboHints);
  $("window_mode").addEventListener("change", () => {
    const abs = $("window_mode").value === "absolute";
    $("absWrap").hidden = !abs;
    $("absHint").hidden = !abs;
    $("daysWrap").hidden = abs;
  });

  try {
    const saved = JSON.parse(localStorage.getItem(LS_KEY) || "null");
    if (saved && saved.remember) {
      $("remember").checked = true;
      if (saved.host) $("host").value = saved.host;
      if (saved.client_id) $("client_id").value = saved.client_id;
    }
  } catch (e) {}

  $("remember").addEventListener("change", () => {
    if (!$("remember").checked) localStorage.removeItem(LS_KEY);
  });

  function persistCreds() {
    if ($("remember").checked) {
      localStorage.setItem(LS_KEY, JSON.stringify({
        remember: true,
        host: $("host").value.trim(),
        client_id: $("client_id").value.trim()
      }));
    }
  }

  function appendLog(lines, replace) {
    if (replace) logEl.textContent = "";
    if (!lines || !lines.length) return;
    logEl.textContent = lines.join("\n");
    logEl.scrollTop = logEl.scrollHeight;
  }

  let timer = null;
  let lastLen = 0;

  async function poll() {
    try {
      const r = await fetch("/api/status", { cache: "no-store" });
      const s = await r.json();
      if (s.lines && s.lines.length !== lastLen) {
        lastLen = s.lines.length;
        appendLog(s.lines, true);
      }
      if (s.running) {
        runState.textContent = "產生中";
        go.disabled = true;
        statusEl.className = "status";
        statusEl.textContent = "正在產生報告，請稍候。同一時間只會跑一份。";
        return;
      }
      go.disabled = false;
      if (s.ok === true) {
        runState.textContent = "完成";
        statusEl.className = "status good";
        const mb = s.bytes ? (s.bytes / 1048576).toFixed(2) + " MB" : "";
        const path = s.out_path ? "已寫入 " + s.out_path : "已寫入 out/ 資料夾";
        statusEl.innerHTML = "完成。" + path + (mb ? "（" + mb + "）" : "") +
          (s.download ? "　<a href=\"" + s.download + "\">下載 HTML</a>" : "");
        if (timer) { clearInterval(timer); timer = null; }
      } else if (s.ok === false) {
        runState.textContent = "失敗";
        statusEl.className = "status bad";
        statusEl.textContent = s.error || "產生失敗。";
        if (timer) { clearInterval(timer); timer = null; }
      } else {
        runState.textContent = "待機";
      }
    } catch (e) {
      statusEl.className = "status bad";
      statusEl.textContent = "無法讀取進度：" + e;
    }
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    persistCreds();
    const body = {
      host: $("host").value.trim(),
      client_id: $("client_id").value.trim(),
      secret: $("secret").value,
      kind: $("kind").value,
      version: $("version").value,
      theme: $("theme").value,
      lang: $("lang").value,
      window_mode: $("window_mode").value,
      days: $("days").value,
      start: $("start").value.trim(),
      end: $("end").value.trim(),
      from_data: $("from_data").checked,
      verify_tls: $("verify_tls").checked,
      workers: 2,
      timeout: 120
    };
    go.disabled = true;
    runState.textContent = "提交中";
    statusEl.className = "status";
    statusEl.textContent = "正在啟動…";
    logEl.innerHTML = '<span class="dim">啟動產生程序…</span>';
    lastLen = 0;
    try {
      const r = await fetch("/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const j = await r.json();
      if (!r.ok || !j.ok) {
        go.disabled = false;
        runState.textContent = "未開始";
        statusEl.className = "status bad";
        statusEl.textContent = j.error || ("HTTP " + r.status);
        return;
      }
      runState.textContent = "產生中";
      if (timer) clearInterval(timer);
      timer = setInterval(poll, 500);
      poll();
    } catch (e) {
      go.disabled = false;
      runState.textContent = "失敗";
      statusEl.className = "status bad";
      statusEl.textContent = String(e);
    }
  });

  setComboHints();
  poll();
})();
