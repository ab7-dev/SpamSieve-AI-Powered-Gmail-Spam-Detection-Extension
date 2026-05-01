/* ============================================================
   SpamSieve — popup.js
   ============================================================ */

function $(id) { return document.getElementById(id); }

// ── LOAD STATS ───────────────────────────────────────────────
chrome.storage.local.get(["stats", "settings"], (data) => {
  const stats = data.stats || { total: 0, spam: 0, safe: 0 };
  $("stat-total").textContent = stats.total;
  $("stat-spam").textContent = stats.spam;
  $("stat-safe").textContent = stats.safe;

  const settings = data.settings || {};
  $("toggle-auto").checked = settings.autoAnalyze !== false;
  $("backend-url").value = settings.backendUrl || "";
});

// ── ANALYZE BUTTON ───────────────────────────────────────────
$("btn-analyze").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url?.includes("mail.google.com")) {
      alert("Please open Gmail first.");
      return;
    }
    chrome.tabs.sendMessage(tab.id, { type: "ANALYZE_NOW" });
    window.close();
  });
});

// ── RESET STATS ──────────────────────────────────────────────
$("btn-reset").addEventListener("click", () => {
  chrome.storage.local.set({ stats: { total: 0, spam: 0, safe: 0 } }, () => {
    $("stat-total").textContent = "0";
    $("stat-spam").textContent = "0";
    $("stat-safe").textContent = "0";
  });
});

// ── SAVE SETTINGS ────────────────────────────────────────────
$("btn-save").addEventListener("click", () => {
  const settings = {
    autoAnalyze: $("toggle-auto").checked,
    backendUrl: $("backend-url").value.trim(),
  };

  chrome.storage.local.set({ settings }, () => {
    // Notify all Gmail tabs of updated settings
    chrome.tabs.query({ url: "https://mail.google.com/*" }, (tabs) => {
      tabs.forEach((tab) => {
        chrome.tabs.sendMessage(tab.id, { type: "SETTINGS_UPDATED", settings });
      });
    });

    const msg = $("saved-msg");
    msg.style.display = "inline";
    setTimeout(() => { msg.style.display = "none"; }, 2000);
  });
});
