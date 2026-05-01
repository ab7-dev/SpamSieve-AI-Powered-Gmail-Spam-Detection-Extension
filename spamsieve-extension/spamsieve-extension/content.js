/* ============================================================
   SpamSieve Chrome Extension — content.js
   Injected into mail.google.com
   ============================================================ */

(function () {
  "use strict";

  // ── CONFIG ──────────────────────────────────────────────
  const CONFIG = {
    autoAnalyze: true,         // auto-analyze on email open
    backendUrl: null,          // set to your Flask/FastAPI URL e.g. "http://localhost:5000/predict"
    debounceMs: 600,
    version: "1.0.0",
  };

  // ── SPAM DETECTION ENGINE ────────────────────────────────
  // This is a keyword-weighted Naive-Bayes-style scorer.
  // Replace analyzeSpam() with a real ML call when ready.

  const SPAM_LEXICON = {
    // High-weight spam triggers (weight 3)
    urgent: 3, "act now": 3, "limited time": 3, "you have won": 3,
    "you've won": 3, "claim your": 3, "click here": 3, "free gift": 3,
    "guaranteed winner": 3, "no cost": 3, "risk-free": 3, "100% free": 3,
    "make money fast": 3, casino: 3, lottery: 3, jackpot: 3,
    "wire transfer": 3, "bank account": 3, "verify your account": 3,
    "unusual activity": 3, "suspicious login": 3, "password expired": 3,
    "confirm your identity": 3, "update your payment": 3,
    "your account will be suspended": 3, "click the link below": 3,
    inheritance: 3, "million dollars": 3, "secret deal": 3,

    // Medium-weight spam signals (weight 2)
    free: 2, winner: 2, prize: 2, cash: 2, profit: 2, income: 2,
    investment: 2, discount: 2, promotion: 2, offer: 2, deal: 2,
    subscribe: 2, unsubscribe: 2, "opt out": 2, earn: 2, reward: 2,
    congratulations: 2, selected: 2, exclusive: 2, "double your": 2,
    weight: 2, diet: 2, pill: 2, medication: 2, prescription: 2,
    pharmacy: 2, viagra: 2, loans: 2, credit: 2, refinance: 2,
    mortgage: 2, "work from home": 2, "be your own boss": 2,
    satisfaction: 2, guarantee: 2, refund: 2, "no obligation": 2,
    "as seen on": 2,

    // Low-weight spam signals (weight 1)
    buy: 1, sell: 1, cheap: 1, order: 1, price: 1, save: 1, sale: 1,
    bonus: 1, gift: 1, trial: 1, sample: 1, opportunity: 1, wealth: 1,
    business: 1, marketing: 1, advertising: 1, click: 1, link: 1,
    verify: 1, account: 1, urgent: 1, important: 1, alert: 1,
    notification: 1, confirm: 1, security: 1,
  };

  const HAM_SIGNALS = {
    // Words that lower spam score
    meeting: -2, calendar: -2, schedule: -2, agenda: -2, project: -2,
    report: -2, presentation: -2, deadline: -2, invoice: -2,
    receipt: -2, statement: -2, update: -2, "re:": -1, "fwd:": -1,
    regards: -1, sincerely: -1, team: -1, colleague: -1, thanks: -1,
    "thank you": -1, attached: -1, attachment: -1, document: -1,
  };

  /**
   * Local spam detection function.
   * ─────────────────────────────────────────────────────────
   * TO CONNECT YOUR ML MODEL:
   *   1. Set CONFIG.backendUrl = "http://localhost:5000/predict"
   *   2. Your Flask endpoint should accept POST JSON:
   *      { "from": "...", "subject": "...", "body": "..." }
   *   3. And return:
   *      { "isSpam": true/false, "confidence": 0.95, "label": "SPAM" }
   *   4. The analyzeSpam() function already handles backend calls.
   *      Just set CONFIG.backendUrl and you're done.
   * ─────────────────────────────────────────────────────────
   */
  async function analyzeSpam(emailData) {
    if (CONFIG.backendUrl) {
      return await callBackend(emailData);
    }
    return localAnalysis(emailData);
  }

  async function callBackend(emailData) {
    try {
      const res = await fetch(CONFIG.backendUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(emailData),
      });
      if (!res.ok) throw new Error("Backend error " + res.status);
      const data = await res.json();
      return {
        isSpam: data.isSpam ?? data.is_spam ?? false,
        confidence: data.confidence ?? data.probability ?? 0.5,
        label: data.label ?? (data.isSpam ? "SPAM" : "SAFE"),
        features: data.features ?? [],
        source: "backend",
      };
    } catch (err) {
      console.warn("[SpamSieve] Backend unreachable, falling back to local:", err);
      return localAnalysis(emailData);
    }
  }

  function localAnalysis({ from = "", subject = "", body = "" }) {
    const text = `${from} ${subject} ${body}`.toLowerCase();
    let spamScore = 0;
    let hamScore = 0;
    const hitWords = [];

    // Score spam lexicon
    for (const [word, weight] of Object.entries(SPAM_LEXICON)) {
      if (text.includes(word)) {
        spamScore += weight;
        hitWords.push({ word, weight, isSpam: true });
      }
    }

    // Score ham signals
    for (const [word, weight] of Object.entries(HAM_SIGNALS)) {
      if (text.includes(word)) {
        hamScore += Math.abs(weight);
        hitWords.push({ word, weight, isSpam: false });
      }
    }

    // Subject-line boosters
    const subjectLower = subject.toLowerCase();
    if (/[A-Z]{5,}/.test(subject)) spamScore += 2;        // ALL CAPS words
    if ((subject.match(/!/g) || []).length >= 2) spamScore += 2; // Multiple !!!
    if (/^\s*re:|^\s*fwd:/i.test(subject)) hamScore += 1;  // Reply/forward

    // Sender domain heuristics
    const senderLower = from.toLowerCase();
    if (/noreply|no-reply|donotreply/.test(senderLower)) spamScore += 1;
    if (/@(gmail|yahoo|outlook|hotmail|proton|icloud)\.com/.test(senderLower)) {
      // Personal domains for marketing mail
      if (spamScore > 3) spamScore += 1;
    }
    if (/@[a-z0-9-]+\.[a-z]{2,3}\.[a-z]{2}$/.test(senderLower)) spamScore += 1; // Suspicious TLDs

    // Body length heuristic
    const wordCount = body.split(/\s+/).filter(Boolean).length;
    if (wordCount < 20 && spamScore > 2) spamScore += 1;  // Very short + spam words

    // Normalize to probability [0,1]
    const net = spamScore - hamScore;
    const norm = Math.max(0, Math.min(1, (net + 2) / 14));
    const threshold = 0.38;

    return {
      isSpam: norm >= threshold,
      confidence: Math.round(norm * 100) / 100,
      label: norm >= threshold ? "SPAM" : "SAFE",
      spamScore,
      hamScore,
      features: hitWords,
      source: "local",
    };
  }

  // ── GMAIL DOM HELPERS ────────────────────────────────────

  function extractEmailData() {
    try {
      // From field
      const fromEl =
        document.querySelector('[data-hovercard-id]') ||
        document.querySelector(".gD") ||
        document.querySelector('[email]');
      const from = fromEl
        ? (fromEl.getAttribute("email") || fromEl.getAttribute("data-hovercard-id") || fromEl.textContent || "")
        : "";

      // Subject
      const subjectEl =
        document.querySelector(".hP") ||
        document.querySelector('[data-thread-perm-id] h2') ||
        document.querySelector(".ha h2");
      const subject = subjectEl ? subjectEl.textContent.trim() : "";

      // Email body — Gmail wraps email text in .a3s.aiL or .ii.gt
      const bodyEls = document.querySelectorAll(".a3s.aiL, .ii.gt .a3s");
      let body = "";
      bodyEls.forEach((el) => {
        // Clone to strip quoted text
        const clone = el.cloneNode(true);
        clone.querySelectorAll(".gmail_quote, .gmail_signature, blockquote").forEach((q) => q.remove());
        body += " " + (clone.textContent || "");
      });
      body = body.replace(/\s+/g, " ").trim().slice(0, 3000); // cap at 3000 chars

      return { from: from.trim(), subject, body };
    } catch (e) {
      return { from: "", subject: "", body: "" };
    }
  }

  function getEmailContainer() {
    // The open email view in Gmail
    return (
      document.querySelector(".AO .nH .if") ||
      document.querySelector('[role="main"] .adn') ||
      document.querySelector(".gs") ||
      document.querySelector(".adn.ads")
    );
  }

  // ── BANNER UI ────────────────────────────────────────────

  const BANNER_ID = "spamsieve-banner";

  function removeBanner() {
    const old = document.getElementById(BANNER_ID);
    if (old) old.remove();
  }

  function createBanner(state = "loading") {
    removeBanner();

    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.className = `ss-banner ss-banner--${state}`;

    if (state === "loading") {
      banner.innerHTML = `
        <div class="ss-banner__inner">
          <div class="ss-spinner"></div>
          <span class="ss-banner__text">SpamSieve is analyzing this email…</span>
        </div>`;
    }

    return banner;
  }

  function showResult(result, emailData) {
    removeBanner();

    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.className = `ss-banner ss-banner--${result.isSpam ? "spam" : "safe"}`;

    const pct = Math.round(result.confidence * 100);
    const barWidth = pct;
    const icon = result.isSpam
      ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
      : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;

    const topKeywords = result.features
      ? result.features.filter((f) => f.isSpam && f.weight >= 2).slice(0, 4).map((f) => f.word)
      : [];

    banner.innerHTML = `
      <div class="ss-banner__inner">
        <div class="ss-banner__icon">${icon}</div>
        <div class="ss-banner__info">
          <span class="ss-banner__label">${result.isSpam ? "⚠ SPAM DETECTED" : "✓ Email Looks Safe"}</span>
          ${topKeywords.length ? `<span class="ss-banner__keywords">Triggers: ${topKeywords.join(", ")}</span>` : ""}
        </div>
        <div class="ss-banner__score">
          <div class="ss-score-bar">
            <div class="ss-score-bar__fill" style="width:${barWidth}%"></div>
          </div>
          <span class="ss-banner__pct">${result.isSpam ? "Spam" : "Safe"} ${pct}%</span>
        </div>
        <button class="ss-btn ss-btn--reanalyze" id="ss-reanalyze" title="Re-analyze">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        </button>
        <button class="ss-btn ss-btn--close" id="ss-close" title="Dismiss">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>`;

    // Wire up buttons
    banner.querySelector("#ss-close").addEventListener("click", removeBanner);
    banner.querySelector("#ss-reanalyze").addEventListener("click", async () => {
      injectBanner("loading");
      const data = extractEmailData();
      const res = await analyzeSpam(data);
      showResult(res, data);
      saveStat(res);
    });

    injectBanner(null, banner);
  }

  function showError(msg) {
    removeBanner();
    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.className = "ss-banner ss-banner--error";
    banner.innerHTML = `
      <div class="ss-banner__inner">
        <span class="ss-banner__text">SpamSieve: ${msg}</span>
        <button class="ss-btn ss-btn--close" id="ss-close">✕</button>
      </div>`;
    banner.querySelector("#ss-close").addEventListener("click", removeBanner);
    injectBanner(null, banner);
  }

  function injectBanner(state, bannerEl) {
    const el = bannerEl || createBanner(state);

    // Try to inject right above the email body
    const targets = [
      document.querySelector(".ha"),           // Email header area
      document.querySelector(".hq"),
      document.querySelector('[role="main"] .nH .if'),
      document.querySelector(".gs"),
    ];

    for (const target of targets) {
      if (target) {
        // Insert after the header, before body
        const parent = target.parentNode;
        if (parent) {
          parent.insertBefore(el, target.nextSibling);
          return;
        }
      }
    }

    // Fallback: prepend to main area
    const main = document.querySelector('[role="main"]');
    if (main) main.prepend(el);
  }

  // ── CORE FLOW ────────────────────────────────────────────

  async function runAnalysis() {
    const data = extractEmailData();

    // Don't analyze if nothing to work with
    if (!data.subject && !data.body && !data.from) return;

    injectBanner("loading");

    try {
      const result = await analyzeSpam(data);
      showResult(result, data);
      saveStat(result);

      // Notify background for badge update
      chrome.runtime.sendMessage({
        type: "ANALYSIS_DONE",
        isSpam: result.isSpam,
        subject: data.subject,
      });
    } catch (err) {
      showError("Analysis failed. " + err.message);
    }
  }

  // ── ADD MANUAL BUTTON ────────────────────────────────────

  const BUTTON_ID = "spamsieve-btn";

  function injectAnalyzeButton() {
    if (document.getElementById(BUTTON_ID)) return;

    // Gmail's toolbar area (.G-Ni.J-J5-Ji)
    const toolbar =
      document.querySelector(".G-Ni.J-J5-Ji") ||
      document.querySelector(".aqK") ||
      document.querySelector(".iH");

    if (!toolbar) return;

    const btn = document.createElement("div");
    btn.id = BUTTON_ID;
    btn.className = "ss-toolbar-btn";
    btn.setAttribute("title", "SpamSieve — Analyze this email");
    btn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span>SpamSieve</span>`;
    btn.addEventListener("click", runAnalysis);
    toolbar.appendChild(btn);
  }

  // ── STATS STORAGE ────────────────────────────────────────

  function saveStat(result) {
    chrome.storage.local.get(["stats"], (data) => {
      const stats = data.stats || { total: 0, spam: 0, safe: 0 };
      stats.total += 1;
      if (result.isSpam) stats.spam += 1;
      else stats.safe += 1;
      stats.lastScan = Date.now();
      chrome.storage.local.set({ stats });
    });
  }

  // ── MUTATION OBSERVER ────────────────────────────────────
  // Watches for Gmail route/email changes without page reload.

  let lastUrl = location.href;
  let analyzeTimeout = null;
  let observerActive = false;

  function debounceAnalyze() {
    clearTimeout(analyzeTimeout);
    analyzeTimeout = setTimeout(() => {
      const isEmailOpen =
        location.href.includes("#inbox/") ||
        location.href.includes("#spam/") ||
        location.href.includes("#all/") ||
        location.href.includes("/mail/u/") ||
        document.querySelector(".ha") !== null;

      if (isEmailOpen) {
        injectAnalyzeButton();
        if (CONFIG.autoAnalyze) runAnalysis();
      }
    }, CONFIG.debounceMs);
  }

  const observer = new MutationObserver((mutations) => {
    const newUrl = location.href;

    // URL changed = new email opened
    if (newUrl !== lastUrl) {
      lastUrl = newUrl;
      removeBanner(); // clear old banner
      debounceAnalyze();
      return;
    }

    // Or a significant DOM change happened
    const significant = mutations.some(
      (m) =>
        m.addedNodes.length > 2 &&
        [...m.addedNodes].some(
          (n) =>
            n.nodeType === 1 &&
            (n.classList?.contains("ha") ||
              n.classList?.contains("adn") ||
              n.querySelector?.(".ha"))
        )
    );

    if (significant) {
      debounceAnalyze();
    }
  });

  function startObserver() {
    if (observerActive) return;
    const root = document.querySelector('[role="main"]') || document.body;
    observer.observe(root, { childList: true, subtree: true });
    observerActive = true;
  }

  // ── INIT ─────────────────────────────────────────────────

  function init() {
    // Load user settings from storage
    chrome.storage.local.get(["settings"], (data) => {
      if (data.settings) {
        CONFIG.autoAnalyze = data.settings.autoAnalyze ?? true;
        CONFIG.backendUrl = data.settings.backendUrl || null;
      }
      startObserver();
      // Trigger initial scan if already in an email
      debounceAnalyze();
    });
  }

  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "ANALYZE_NOW") runAnalysis();
    if (msg.type === "SETTINGS_UPDATED") {
      CONFIG.autoAnalyze = msg.settings.autoAnalyze ?? true;
      CONFIG.backendUrl = msg.settings.backendUrl || null;
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
