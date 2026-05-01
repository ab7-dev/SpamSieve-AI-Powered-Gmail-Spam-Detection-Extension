# 🛡️ SpamSieve — Gmail Chrome Extension

Real-time spam detection injected directly into Gmail.  
Built to integrate with your SpamSieve AI project.

---

## 📁 Folder Structure

```
spamsieve-extension/
├── manifest.json       ← Extension config (Manifest V3)
├── content.js          ← Injected into Gmail — core logic
├── background.js       ← Service worker — badge updates
├── popup.html          ← Extension popup UI
├── popup.js            ← Popup logic
├── styles.css          ← Injected Gmail styles
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## 🚀 How to Load the Extension in Chrome

1. Open Chrome and go to: `chrome://extensions`
2. Enable **Developer Mode** (top-right toggle)
3. Click **"Load unpacked"**
4. Select the `spamsieve-extension/` folder
5. The SpamSieve shield icon will appear in your Chrome toolbar ✅

---

## 🧪 How to Test in Gmail

1. Go to [mail.google.com](https://mail.google.com)
2. Open any email
3. A banner will automatically appear **above the email body** showing:
   - ⚠ **SPAM DETECTED** (red) — with confidence % and trigger words
   - ✓ **Email Looks Safe** (green) — with confidence %
4. Click the **"SpamSieve"** button in Gmail's toolbar to manually re-analyze
5. Click the extension icon in Chrome toolbar to:
   - See scan statistics
   - Toggle auto-analyze on/off
   - Connect your ML backend

---

## 🧠 How the Spam Detection Works (Local Mode)

The built-in detector uses a **weighted keyword scoring system**:

```
SpamScore  = sum of spam keyword weights found in email
HamScore   = sum of ham (safe) signal weights
Probability = normalize(SpamScore - HamScore) → [0, 1]
IsSpam     = Probability >= 0.38 (adjustable threshold)
```

**Additional signals checked:**
- ALL CAPS words in subject line → +2
- Multiple exclamation marks → +2  
- Reply/Forward prefix (Re:/Fwd:) → -1
- `noreply@` sender → +1
- Very short emails with spam words → +1

---

## 🔌 Connecting Your ML Backend (Flask / FastAPI)

### Step 1 — Set the backend URL in the extension popup
Click the SpamSieve icon → enter your URL:
```
http://localhost:5000/predict
```

### Step 2 — Your Flask endpoint (example)

```python
# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # ← Important! Allows Chrome extension to call it

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    
    sender  = data.get('from', '')
    subject = data.get('subject', '')
    body    = data.get('body', '')
    
    # ─── PLUG YOUR MODEL HERE ───────────────────────────
    # Example with your existing model:
    # features = extract_features(sender, subject, body)
    # prob = model.predict_proba([features])[0][1]
    # is_spam = prob >= 0.5
    #
    # For now, a placeholder:
    text = f"{sender} {subject} {body}".lower()
    is_spam = any(w in text for w in ['free', 'winner', 'click here', 'urgent'])
    prob = 0.85 if is_spam else 0.12
    # ────────────────────────────────────────────────────
    
    return jsonify({
        "isSpam": is_spam,
        "confidence": prob,
        "label": "SPAM" if is_spam else "SAFE"
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

### Step 3 — Run your server
```bash
pip install flask flask-cors
python app.py
```

### Step 4 — FastAPI version (alternative)

```python
# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class EmailRequest(BaseModel):
    from_: str = ""
    subject: str = ""
    body: str = ""

@app.post("/predict")
def predict(email: EmailRequest):
    # Plug your model here
    return {"isSpam": False, "confidence": 0.1, "label": "SAFE"}
```

```bash
pip install fastapi uvicorn
uvicorn main:app --port 5000
```

---

## ⚠️ Common Errors & Fixes

| Error | Cause | Fix |
|---|---|---|
| Banner doesn't appear | Gmail DOM changed | Click the SpamSieve toolbar button to re-analyze manually |
| "Analysis failed" message | JS error in content.js | Open DevTools (F12) → Console → look for `[SpamSieve]` errors |
| Extension not loading | manifest.json syntax error | Check `chrome://extensions` for the red error message |
| Backend CORS error | Flask missing CORS headers | Add `flask-cors` and `CORS(app)` |
| Icons missing | PNG files absent | Re-download or replace with any 16/48/128px PNG |
| Auto-analyze not working | Setting is off | Click extension icon → enable "Auto-analyze on open" |
| Doesn't detect email open | Gmail SPA routing | The MutationObserver watches URL changes — try navigating away and back |

---

## 🔧 Customizing the Spam Threshold

In `content.js`, find:
```js
const threshold = 0.38;
```
- Increase (e.g. `0.55`) → fewer false positives, may miss some spam
- Decrease (e.g. `0.25`) → catches more spam, more false positives

---

## 📊 Where to Plug Your Existing SpamSieve Model

In `content.js`, find the `localAnalysis()` function and replace it with a call to `callBackend()`, or modify the keyword lexicon (`SPAM_LEXICON`) to match your model's vocabulary.

The `analyzeSpam()` function is the single entry point:
```js
async function analyzeSpam(emailData) {
    if (CONFIG.backendUrl) {
        return await callBackend(emailData);  // ← Your model via HTTP
    }
    return localAnalysis(emailData);           // ← Built-in keyword engine
}
```

---

## 📝 Notes for College Project Submission

- All spam detection logic is in `content.js` under `localAnalysis()`
- The extension is **Manifest V3** compliant (latest Chrome standard)
- No external dependencies — pure vanilla JS
- Gmail is never modified destructively — the banner is non-invasive
- All settings persist via `chrome.storage.local`

---

*SpamSieve Extension v1.0 — Built with ❤️ for real-time Gmail protection*
