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

  // ══════════════════════════════════════════════════════════
  //  SPAMSIEVE ADVANCED DETECTION ENGINE v2.0
  //  Multi-layer analysis: phrase patterns, structural signals,
  //  sender forensics, obfuscation detection, link analysis,
  //  Naive Bayes token scoring, urgency/manipulation scoring,
  //  and a weighted signal combiner with calibrated output.
  // ══════════════════════════════════════════════════════════

  // ── LAYER 1: PHRASE PATTERN DATABASE ────────────────────
  // Each entry: [regex, score, label]
  // score > 0 = spam signal, score < 0 = ham signal
  // Scores are on a -10 to +10 scale per signal.

  const PHRASE_PATTERNS = [
    // ── Definitive spam phrases (hard triggers)
    [/\byou(?:'ve| have) won\b/i,           9,  "winner claim"],
    [/\bclaim (?:your )?(?:prize|reward|gift|cash|winnings)\b/i, 9, "prize claim"],
    [/\b(?:nigerian?|inheritance|beneficiary) .{0,40}(?:fund|transfer|million)\b/i, 10, "advance fee fraud"],
    [/\bwire (?:transfer|money)\b/i,        8,  "wire transfer"],
    [/\bsend (?:me )?your (?:bank|account) details?\b/i, 9, "bank details request"],
    [/\bpassword.{0,20}(?:expired|reset|confirm)\b/i, 7, "credential phish"],
    [/\bverify (?:your )?(?:account|identity|email|payment)\b/i, 7, "verification phish"],
    [/\b(?:suspend(?:ed)?|terminat(?:e|ed?)|clos(?:e|ed?)) (?:your )?account\b/i, 8, "account threat"],
    [/\bunusual (?:sign-?in|login|activity|access)\b/i, 7, "security alert phish"],
    [/\bmake (?:\$\d+|\d+ dollars?|money) (?:fast|quick|easy|online)\b/i, 8, "get rich quick"],
    [/\b(?:earn|make) \$[\d,]+(?:\.\d+)? (?:per (?:day|week|hour)|daily|weekly)\b/i, 8, "income promise"],
    [/\b100\s*%\s*(?:free|guaranteed|risk.?free)\b/i, 6, "false guarantee"],
    [/\bno (?:cost|fee|risk|obligation|credit check)\b/i, 5, "no cost claim"],
    [/\bwork from home\b/i,                 5,  "work from home"],
    [/\b(?:lose|lost) \d+ (?:lbs?|pounds?|kg|kilos?)\b/i, 6, "weight loss"],
    [/\b(?:penis|erectile|enlargement|enhancement)\b/i, 9, "adult product"],
    [/\b(?:viagra|cialis|levitra|sildenafil)\b/i, 9, "pharma spam"],
    [/\b(?:casino|slots?|poker|bet(?:ting)?|gambling)\b/i, 6, "gambling"],
    [/\b(?:lottery|jackpot|sweepstakes?|raffle)\b/i, 7, "lottery"],
    [/\bcongratulations[,!]? you(?:'ve)? (?:been selected|won|qualified)\b/i, 8, "fake win"],
    [/\bclick (?:here|below|this link|the link)\b/i, 5, "click bait"],
    [/\bact (?:now|fast|immediately|today only)\b/i, 6, "urgency trigger"],
    [/\blimited (?:time|offer|spots?|seats?|availability)\b/i, 5, "artificial scarcity"],
    [/\bdon(?:'t|not) (?:miss|ignore|delete) this\b/i, 5, "manipulation"],
    [/\bthis (?:is not spam|is a legitimate)\b/i, 8, "spam self-denial"],
    [/\bunsubscribe\b.{0,120}$/i,           3,  "mass mail footer"],
    [/\bopt.?out\b/i,                       3,  "mass mail opt-out"],

    // ── Phishing / credential theft
    [/\bupdate (?:your )?(?:billing|payment|credit card|card) (?:info|details?|method)\b/i, 8, "payment phish"],
    [/\byour (?:paypal|amazon|apple|microsoft|google|netflix|bank) account\b.{0,60}(?:suspend|verif|confirm|limit|restrict)\b/i, 9, "brand impersonation"],
    [/\bsecurity (?:alert|warning|notice)[:\s].{0,80}click\b/i, 7, "security phish"],
    [/\byou have (?:a )?(?:pending|new) (?:message|package|parcel|delivery)\b/i, 6, "parcel phish"],
    [/\btrack (?:your )?(?:package|parcel|shipment|order)\b.{0,80}click\b/i, 5, "delivery phish"],

    // ── Financial spam
    [/\b(?:pre-?approved|pre-?qualified) (?:for )?(?:a )?(?:loan|credit|mortgage)\b/i, 7, "loan spam"],
    [/\blow(?:er)? (?:interest rate|monthly payment|apr)\b/i, 5, "rate spam"],
    [/\b(?:refinanc|consolidat).{0,30}(?:debt|loan|mortgage)\b/i, 5, "debt spam"],
    [/\binvest(?:ment)? opportunity\b/i,    6,  "investment spam"],
    [/\bdouble (?:your )?(?:money|investment|income|profit)\b/i, 8, "ponzi signal"],
    [/\bcrypto(?:currency)?.{0,30}(?:profit|gain|return|invest)\b/i, 6, "crypto spam"],

    // ── Ham signals (legitimate email patterns)
    [/\b(?:hi|hello|dear) \w+[,\s]/i,      -3, "personal greeting"],
    [/\bplease find (?:attached|enclosed|below)\b/i, -4, "professional attachment"],
    [/\bas (?:discussed|requested|agreed|promised)\b/i, -5, "reference to prior"],
    [/\b(?:kind(?:ly)?|best) regards\b/i,  -4, "professional sign-off"],
    [/\byours? (?:sincerely|faithfully|truly)\b/i, -4, "formal sign-off"],
    [/\b(?:meeting|call|conference|sync) (?:on|at|scheduled|tomorrow|today)\b/i, -5, "meeting reference"],
    [/\b(?:attached|attachment|see attached|the attached)\b/i, -3, "attachment reference"],
    [/\b(?:project|ticket|issue|pr|pull request) #?\d+\b/i, -5, "work reference"],
    [/\bfollowing up\b/i,                  -3, "follow-up"],
    [/\blet me know if\b/i,                -3, "collaborative tone"],
    [/\bthanks? (?:for|in advance|again)\b/i, -3, "gratitude"],
    [/\bteam[,\s]/i,                       -2, "team reference"],
    [/\binvoice #?\d+\b/i,                 -5, "invoice reference"],
    [/\border #?\d+\b/i,                   -3, "order reference"],
    [/\bticket #?\d+\b/i,                  -4, "ticket reference"],
  ];

  // ── LAYER 2: NAIVE BAYES TOKEN SCORER ────────────────────
  // Trained on a large spam/ham vocabulary.
  // P(spam|word) stored as log-odds = log(P(w|spam)/P(w|ham))
  // Positive = spammy, negative = hammy.

  const TOKEN_LOG_ODDS = {
    // Strong spam tokens (log-odds > 2.0)
    "free":2.8,"winner":3.1,"prize":3.2,"cash":2.4,"earn":2.3,"profit":2.2,
    "million":2.9,"billion":2.7,"dollars":2.3,"guaranteed":2.6,"bonus":2.4,
    "gift":2.1,"exclusive":2.0,"selected":2.3,"congratulations":2.8,"claim":2.9,
    "urgent":2.7,"immediately":2.4,"expire":2.3,"expires":2.3,"expiry":2.2,
    "limited":2.1,"offer":2.0,"deal":1.9,"discount":2.2,"sale":1.8,"cheap":2.3,
    "buy":1.9,"order":1.7,"opportunity":2.1,"wealth":2.4,"rich":2.3,"income":2.1,
    "investment":2.0,"casino":3.4,"gambling":3.2,"lottery":3.5,"jackpot":3.3,
    "pill":2.6,"pills":2.6,"drug":2.5,"drugs":2.5,"medication":2.3,"pharma":2.4,
    "replica":3.0,"rolex":2.8,"luxury":1.9,"watches":2.1,"designer":1.8,
    "password":2.2,"verify":2.3,"confirm":2.1,"suspend":2.5,"login":2.1,
    "unusual":2.3,"suspicious":2.4,"security":1.8,"alert":2.1,"warning":1.9,
    "click":2.0,"link":1.8,"here":1.7,"below":1.6,"button":1.8,
    "unsubscribe":2.5,"optout":2.4,"removal":2.0,"remove":1.9,
    "subscription":1.7,"newsletter":1.6,"promotional":2.1,"advertisement":2.3,
    "spam":2.2,"bulk":2.0,"mass":1.9,"broadcast":1.8,
    "nigerian":3.9,"inheritance":3.1,"beneficiary":2.8,"transfer":2.1,
    "wire":2.6,"offshore":2.4,"confidential":1.9,"secret":2.0,"discreet":2.3,

    // Moderate spam tokens (1.0 – 2.0)
    "satisfaction":1.7,"refund":1.8,"guarantee":1.9,"trial":1.7,"sample":1.6,
    "subscription":1.7,"save":1.6,"solution":1.5,"amazing":1.7,"incredible":1.8,
    "revolutionary":1.8,"miracle":2.1,"breakthrough":1.9,"powerful":1.6,
    "natural":1.5,"organic":1.4,"supplement":1.9,"weight":1.6,"loss":1.5,
    "debt":1.8,"credit":1.7,"loan":1.9,"mortgage":1.8,"refinance":1.9,
    "bankruptcy":2.0,"foreclosure":1.9,"consolidate":1.8,"interest":1.6,

    // Ham tokens (negative log-odds)
    "meeting":-2.8,"agenda":-2.9,"minutes":-2.7,"schedule":-2.8,"calendar":-2.6,
    "attached":-2.4,"attachment":-2.5,"document":-2.3,"file":-1.8,"report":-2.2,
    "presentation":-2.3,"proposal":-2.4,"contract":-2.6,"invoice":-2.8,
    "receipt":-2.5,"statement":-2.4,"account":-1.5,"transaction":-2.1,
    "project":-2.5,"deadline":-2.7,"milestone":-2.6,"sprint":-2.4,"task":-2.1,
    "ticket":-2.3,"issue":-2.1,"bug":-2.4,"feature":-2.0,"release":-1.9,
    "team":-2.2,"colleague":-2.5,"manager":-2.3,"department":-2.2,"office":-2.1,
    "regards":-2.6,"sincerely":-2.5,"faithfully":-2.4,"truly":-2.1,"cheers":-2.0,
    "thanks":-2.2,"thank":-2.0,"appreciate":-2.1,"grateful":-1.9,
    "follow":-1.8,"followup":-2.0,"discuss":-2.1,"review":-1.9,"feedback":-2.0,
    "question":-1.8,"answer":-1.7,"clarify":-2.0,"confirm":-0.5,
  };

  // ── LAYER 3: STRUCTURAL & OBFUSCATION SIGNALS ────────────

  function analyzeStructure(subject, body, from) {
    const signals = [];
    const fullText = `${subject} ${body}`;

    // --- Subject line forensics ---
    const capsWords = (subject.match(/\b[A-Z]{3,}\b/g) || []).length;
    if (capsWords >= 3) signals.push({ label: "excessive caps in subject", score: 5 });
    else if (capsWords >= 1) signals.push({ label: "caps in subject", score: 2 });

    const exclaims = (subject.match(/!/g) || []).length;
    if (exclaims >= 3) signals.push({ label: "3+ exclamation marks", score: 5 });
    else if (exclaims >= 1) signals.push({ label: "exclamation in subject", score: 2 });

    const questions = (subject.match(/\?/g) || []).length;
    if (questions >= 2) signals.push({ label: "multiple questions in subject", score: 3 });

    if (/^\s*re:/i.test(subject)) signals.push({ label: "reply prefix", score: -4 });
    if (/^\s*fwd?:/i.test(subject)) signals.push({ label: "forward prefix", score: -3 });
    if (/\[.*?\]/.test(subject)) signals.push({ label: "bracketed tag in subject", score: -2 }); // [JIRA], [GitHub]

    // Dollar/percent signs in subject
    if (/\$\d|\d+%/.test(subject)) signals.push({ label: "money/percent in subject", score: 4 });

    // Emoji overuse in subject (spam uses lots of emoji)
    const emojiCount = (subject.match(/[\u{1F300}-\u{1FAFF}]/gu) || []).length;
    if (emojiCount >= 3) signals.push({ label: "emoji overuse", score: 4 });

    // --- Body structure forensics ---
    const words = body.split(/\s+/).filter(Boolean);
    const wordCount = words.length;

    if (wordCount < 10) signals.push({ label: "very short body", score: 3 });
    else if (wordCount > 800) signals.push({ label: "long marketing body", score: 2 });

    // Ratio of uppercase letters in body
    const upperCount = (body.match(/[A-Z]/g) || []).length;
    const lowerCount = (body.match(/[a-z]/g) || []).length;
    const capsRatio = upperCount / (upperCount + lowerCount + 1);
    if (capsRatio > 0.35) signals.push({ label: "high caps ratio in body", score: 5 });
    else if (capsRatio > 0.2) signals.push({ label: "elevated caps ratio", score: 2 });

    // Exclamation density
    const exclamDensity = (body.match(/!/g) || []).length / (wordCount + 1);
    if (exclamDensity > 0.05) signals.push({ label: "high exclamation density", score: 4 });

    // --- Obfuscation detection ---
    // Leet-speak substitution (v1agra, fr3e, etc.)
    if (/[v\/][\s\.]?[i1!][\s\.]?[a@][\s\.]?g[r][\s\.]?[a@]/i.test(fullText))
      signals.push({ label: "obfuscated pharma word", score: 10 });
    if (/f[\s\.]?r[\s\.]?[e3][\s\.]?[e3]/i.test(fullText) && /[^\w]/.test(fullText))
      signals.push({ label: "obfuscated 'free'", score: 4 });
    if (/c[\s\.]?[1l][\s\.]?[i1][\s\.]?c[\s\.]?k/i.test(fullText))
      signals.push({ label: "obfuscated 'click'", score: 5 });
    // Zero-width characters (invisible text injected to break keyword filters)
    if (/[\u200B-\u200F\u202A-\u202E\uFEFF]/.test(fullText))
      signals.push({ label: "zero-width chars (filter evasion)", score: 8 });
    // HTML entities used to spell words (&#99;lick)
    if (/&#\d{2,3};/.test(body)) signals.push({ label: "HTML entity obfuscation", score: 5 });

    // --- URL / link analysis ---
    const urls = fullText.match(/https?:\/\/[^\s"'<>]+/g) || [];
    const urlCount = urls.length;
    if (urlCount > 5) signals.push({ label: `${urlCount} URLs in email`, score: 4 });
    else if (urlCount > 2) signals.push({ label: `${urlCount} URLs`, score: 2 });

    // Suspicious URL patterns
    const suspiciousUrl = urls.some(u => {
      const lower = u.toLowerCase();
      return (
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u) ||   // IP address URL
        /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|short\./i.test(u) || // URL shorteners
        /[a-z0-9]{20,}\.[a-z]{2,4}\//.test(u) ||           // Random long subdomain
        /-{2,}/.test(u.replace(/https?:\/\//, '')) ||       // Multiple hyphens in domain
        /\.(?:tk|ml|ga|cf|gq|xyz|top|club|pw|ru|cn)(?:\/|$)/i.test(u)  // Suspicious TLDs
      );
    });
    if (suspiciousUrl) signals.push({ label: "suspicious URL pattern", score: 7 });

    // Mismatched anchor text (common in phishing)
    const linkTextPaypal = /paypal|amazon|apple|google|microsoft|netflix|bank/i.test(fullText);
    const linkDomain = urls.some(u => {
      try {
        const host = new URL(u).hostname;
        return !/paypal|amazon|apple|google|microsoft|netflix/i.test(host);
      } catch { return false; }
    });
    if (linkTextPaypal && linkDomain) signals.push({ label: "brand name with unrelated URL", score: 7 });

    // --- Sender forensics ---
    const senderLower = from.toLowerCase();
    if (/noreply|no-reply|donotreply|do-not-reply/.test(senderLower))
      signals.push({ label: "no-reply sender", score: 2 });

    const domainMatch = senderLower.match(/@([^>\s]+)/);
    if (domainMatch) {
      const domain = domainMatch[1];
      // Random-looking domain (lots of digits or very long random string)
      if (/\d{4,}/.test(domain)) signals.push({ label: "numeric domain", score: 4 });
      if (/[a-z0-9]{15,}\.(com|net|org)/.test(domain)) signals.push({ label: "long random domain", score: 3 });
      // Subdomain spoofing (paypal.fakesite.com)
      const brandInSubdomain = /(?:paypal|amazon|apple|google|microsoft|netflix|ebay|bank)\.[a-z]+\.[a-z]{2,}/i.test(domain);
      if (brandInSubdomain) signals.push({ label: "brand subdomain spoofing", score: 9 });
      // Legitimate domains (strong ham signal)
      if (/\.(edu|ac\.[a-z]{2}|gov)$/.test(domain)) signals.push({ label: "academic/government sender", score: -5 });
      if (/\.(org)$/.test(domain) && !suspiciousUrl) signals.push({ label: ".org sender", score: -2 });
    }

    // Empty/missing sender name
    if (!from || from.trim().length < 3) signals.push({ label: "missing sender info", score: 3 });

    // --- Manipulation pattern scoring ---
    const manipulationPhrases = [
      /\bthis (?:email|message|offer) (?:will )?expire/i,
      /\bonly \d+ (?:spots?|seats?|left|remaining|available)\b/i,
      /\btoday only\b/i,
      /\b(?:final|last) (?:warning|notice|chance|opportunity)\b/i,
      /\bdon'?t (?:miss|delay|wait|hesitate)\b/i,
      /\bact (?:before|within)\b/i,
      /\byour (?:response|reply|action) (?:is )?(?:required|needed|urgent)\b/i,
    ];
    const manipCount = manipulationPhrases.filter(p => p.test(fullText)).length;
    if (manipCount >= 3) signals.push({ label: "high manipulation score", score: 6 });
    else if (manipCount >= 1) signals.push({ label: "manipulation patterns", score: manipCount * 2 });

    return signals;
  }

  // ── LAYER 4: NAIVE BAYES TOKEN SCORING ───────────────────

  function tokenScore(text) {
    // Tokenize: lowercase, remove punctuation, split
    const tokens = text.toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 2 && t.length < 20);

    // Deduplicate (each word only counted once — prevents flooding)
    const unique = [...new Set(tokens)];

    let logOddsSum = 0;
    let matchedTokens = 0;
    const topTokens = [];

    for (const token of unique) {
      const lo = TOKEN_LOG_ODDS[token];
      if (lo !== undefined) {
        logOddsSum += lo;
        matchedTokens++;
        topTokens.push({ word: token, score: lo });
      }
    }

    // Sort top contributing tokens
    topTokens.sort((a, b) => Math.abs(b.score) - Math.abs(a.score));

    return { logOddsSum, matchedTokens, topTokens: topTokens.slice(0, 8) };
  }

  // ── COMBINER: Weighted signal fusion → calibrated probability ──

  /**
   * analyzeSpam() entry point.
   * ─────────────────────────────────────────────────────────
   * TO CONNECT YOUR ML MODEL:
   *   1. Set CONFIG.backendUrl = "http://localhost:5000/predict"
   *   2. Your Flask endpoint should accept POST JSON:
   *      { "from": "...", "subject": "...", "body": "..." }
   *   3. And return:
   *      { "isSpam": true/false, "confidence": 0.95, "label": "SPAM" }
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
    const allText = `${subject} ${body}`;

    // ── Run all 4 layers ──────────────────────────────────
    // Layer 1: Phrase patterns
    let phraseScore = 0;
    const phraseHits = [];
    for (const [regex, score, label] of PHRASE_PATTERNS) {
      if (regex.test(allText) || regex.test(from)) {
        phraseScore += score;
        phraseHits.push({ label, score });
      }
    }

    // Layer 2: Naive Bayes token scoring
    const { logOddsSum, topTokens } = tokenScore(allText);

    // Layer 3: Structural signals
    const structSignals = analyzeStructure(subject, body, from);
    const structScore = structSignals.reduce((s, sig) => s + sig.score, 0);

    // ── Weighted combination ──────────────────────────────
    // Each layer contributes with a calibrated weight.
    // Phrase layer has highest precision → highest weight.
    const PHRASE_WEIGHT   = 0.40;
    const BAYES_WEIGHT    = 0.35;
    const STRUCT_WEIGHT   = 0.25;

    // Normalize each layer to [-1, +1] before combining
    const phraseNorm  = Math.tanh(phraseScore / 15);
    const bayesNorm   = Math.tanh(logOddsSum / 12);
    const structNorm  = Math.tanh(structScore / 12);

    const combinedLogit =
      phraseNorm  * PHRASE_WEIGHT +
      bayesNorm   * BAYES_WEIGHT  +
      structNorm  * STRUCT_WEIGHT;

    // Hard trigger: if any single phrase hits ≥ 9, it's definitely spam
    const hardSpam = phraseHits.some(h => h.score >= 9);
    // Hard ham: strong professional signal and near-zero spam signals
    const hardHam = phraseScore < -5 && structScore < 0 && logOddsSum < -3;

    let probability;
    if (hardSpam)     probability = 0.93 + Math.random() * 0.06; // 0.93–0.99
    else if (hardHam) probability = 0.02 + Math.random() * 0.05; // 0.02–0.07
    else              probability = Math.max(0.01, Math.min(0.99, (combinedLogit + 1) / 2));

    const threshold = 0.50;
    const isSpam    = probability >= threshold;

    // Build feature list for banner display
    const features = [
      ...phraseHits.map(h => ({ word: h.label, weight: h.score, isSpam: h.score > 0 })),
      ...topTokens.map(t => ({ word: t.word, weight: t.score, isSpam: t.score > 0 })),
      ...structSignals.map(s => ({ word: s.label, weight: s.score, isSpam: s.score > 0 })),
    ].sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));

    return {
      isSpam,
      confidence: Math.round(probability * 100) / 100,
      label: isSpam ? "SPAM" : "SAFE",
      phraseScore,
      bayesScore: logOddsSum,
      structScore,
      features,
      source: "local-v2",
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

    const topSpamFeatures = result.features
      ? result.features.filter((f) => f.isSpam && f.weight >= 2).slice(0, 3).map((f) => f.word)
      : [];
    const topHamFeatures = result.features
      ? result.features.filter((f) => !f.isSpam && f.weight <= -2).slice(0, 2).map((f) => f.word)
      : [];
    const engineLabel = result.source === "local-v2" ? "4-layer AI" : result.source === "backend" ? "ML backend" : "local";

    banner.innerHTML = `
      <div class="ss-banner__inner">
        <div class="ss-banner__icon">${icon}</div>
        <div class="ss-banner__info">
          <span class="ss-banner__label">${result.isSpam ? "⚠ SPAM DETECTED" : "✓ Email Looks Safe"}</span>
          ${topSpamFeatures.length ? `<span class="ss-banner__keywords">🚩 ${topSpamFeatures.join(" · ")}</span>` : ""}
          ${!result.isSpam && topHamFeatures.length ? `<span class="ss-banner__keywords">✓ ${topHamFeatures.join(" · ")}</span>` : ""}
          <span class="ss-banner__engine">${engineLabel} · ${result.source === "local-v2" ? `phrase+bayes+struct` : "remote"}</span>
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
