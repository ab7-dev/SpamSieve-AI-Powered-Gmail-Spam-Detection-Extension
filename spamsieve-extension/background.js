/* ============================================================
   SpamSieve — background.js (Manifest V3 Service Worker)
   Handles badge updates and cross-tab messaging.
   ============================================================ */

chrome.runtime.onInstalled.addListener(() => {
  console.log("[SpamSieve] Extension installed.");
  chrome.action.setBadgeBackgroundColor({ color: "#4285f4" });
  chrome.action.setBadgeText({ text: "" });

  // Set default settings
  chrome.storage.local.get(["settings"], (data) => {
    if (!data.settings) {
      chrome.storage.local.set({
        settings: { autoAnalyze: true, backendUrl: "" },
        stats: { total: 0, spam: 0, safe: 0 },
      });
    }
  });
});

// Update badge when analysis result comes in
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === "ANALYSIS_DONE") {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    if (msg.isSpam) {
      chrome.action.setBadgeText({ text: "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#ea4335", tabId });
      chrome.action.setTitle({ title: `SpamSieve — SPAM: ${msg.subject || "unknown"}`, tabId });
    } else {
      chrome.action.setBadgeText({ text: "✓", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#34a853", tabId });
      chrome.action.setTitle({ title: "SpamSieve — Email looks safe", tabId });
    }
  }
});
