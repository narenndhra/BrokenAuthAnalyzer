# BrokenAuth Analyzer – Automated Broken Authentication Testing for Burp Suite

BrokenAuth Analyzer is a **Burp Suite Jython extension** that automates large-scale checks for **Broken Authentication** by mutating only **session-bearing headers** (e.g., `Authorization`, `Cookie`, `X-Session-Token`) and intelligently analyzing server responses.

It eliminates repetitive manual tampering by generating two focused mutations per request and summarizing results with strong, low-noise signals — directly inside Burp.

---

## 🚀 Why This Tool Exists

Systematically testing auth robustness in Burp is usually manual: remove/blank session headers, resend, compare, and decide if a response is a real bypass or just an error page with 200. At scale, this is slow and error-prone.

BrokenAuth Analyzer automates that work:
- Detects **present** session headers per request (case-insensitive).
- Runs **Removed All Session Headers** and **Stripped All Session Headers** mutations.
- Computes **Delta Size**, **Body Similarity**, and **Header Diff** to separate true bypasses from noisy 2xx.
- Rolls up signals by **URL + Method** for executive-friendly summaries.

This means **faster coverage, clearer signal, and fewer missed auth issues**.

---

## ✨ Key Highlights

- **Targeted Mutations (per request, per method)**
  - **Removed All Session Headers** – drops only the detected session headers.
  - **Stripped All Session Headers** – keeps header names but empties values.
- **Per-Method Coverage** for the same path: GET/POST/DELETE are tested **independently**.
- **De-dupe That Respects Reality**: suppresses exact duplicates only (protocol/host/port + method + URL + mode + normalized header set + body checksum).
- **Intelligent Verdicts & Confidence**
  - `VULNERABLE`, `AUTH_ENFORCED`, `INPUT_ERROR`, `ROUTING_ERROR`, `SERVER_ERROR`, `NOT_VULNERABLE_EXPECTED_2XX`, `NOT_VULNERABLE_STATIC`, `AT_RISK` (roll-up), `UNKNOWN`.
- **Strong Signals**
  - **Delta Size**: `len(mutated_response) − len(baseline_response)`
  - **Body Similarity**: Jaccard over alphanumeric tokens (0–100%)
  - **Header Diff**: chip `+/-/~` with tooltip showing full before/after
- **Static Noise Reduction**
  - Treats common static assets (`.js, .css, .png, .jpg, .svg, .woff*`, etc.) and CTs (`image/*`, `text/css`, `*javascript`) as **NOT_VULNERABLE_STATIC** for 2xx on **GET**.
  - Never marks server-side extensions (`.php, .asp, .aspx, .jsp, .do, .action, .cfm, .cgi, .pl, .rb, .py, .go`) as static.
- **UI for Triage**
  - **Summary**: metrics, status code summary, and **Insights** table (sortable; roll-up by URL+Method).
  - **Dashboard**: row-level results with inline Request/Response and **Resend Selected**.
  - **Settings**: session header grid + custom header add; **Auto Scan** for **Proxy & Repeater**.
- **One-Click Data Capture**
  - **Save CSV** → `brokenauth_insights.csv` (append)
  - **Save JSON (JSONL)** → `brokenauth_insights.jsonl` (append)
  - Files are written next to the `.py` (fallback: CWD → user home).

---

## ⚙️ How It Works

1. **Observe Requests**  
   The extension watches Proxy and Repeater (when Auto Scan is on) and also accepts manual sends via context menu.
2. **Detect Session Headers**  
   Only headers present in the original request and matching the selected set are targeted (case-insensitive).
3. **Mutate**  
   - **Removed All Session Headers**  
   - **Stripped All Session Headers**
4. **Send & Compare**  
   - Compute **Delta Size**, **Body Similarity**, and **Header Diff** vs baseline.  
   - Assign a **verdict** and **confidence**.
5. **Summarize**  
   - **Dashboard** shows each mutation row.  
   - **Summary → Insights** aggregates and (optionally) **rolls up by URL+Method** to surface `AT_RISK` endpoints quickly.

> Tip: “2xx + High Similarity (≥ 90%) + Small Delta + innocuous Header Diff” is a strong broken-auth signal.  
> “2xx + Low Similarity + Big Delta” often indicates an error page returning HTTP 200 — not a real bypass.

---

## 📊 UI Overview

### Summary
- **Metrics**: project base URL, # tested (unique method+path), total 2xx.
- **Status Code Summary**: count by code.
- **Insights** (columns): `URL | Mode | Verdict | Severity | Confidence | Baseline | Mutated | Delta Size | Similarity | Header Diff | Signals | Notes`  
  - **Roll-up**: toggle “Group by URL+Method” to see one line per endpoint+method with a combined verdict (`AT_RISK` if any mutated 2xx suggests bypass).  
  - **Notes**: editable; saved in CSV/JSONL.

### Dashboard
- Table of results (red = VULNERABLE, green = SAFE).
- Inline **Request / Response** viewer.
- **Resend Selected** button for quick manual validation.

### Settings
- Checkboxes for common session headers + **Add custom**.
- Select All / None.
- **Enable Auto Scan** for **Proxy & Repeater**.
- **Apply Header Settings**.

---

## 🧮 Verdicts & Severity

| Verdict                         | Meaning                                                   | Default Severity |
|---------------------------------|-----------------------------------------------------------|------------------|
| VULNERABLE                      | Mutated 2xx on non-static → likely auth bypass           | HIGH             |
| AT_RISK (roll-up)               | Any mutation suggests bypass for URL+Method               | HIGH             |
| AUTH_ENFORCED                   | 401/403                                                   | LOW              |
| NOT_VULNERABLE_EXPECTED_2XX     | 2xx where session isn’t required                          | LOW              |
| NOT_VULNERABLE_STATIC           | 2xx static content (GET + static ext/CT)                  | LOW              |
| INPUT_ERROR                     | 400/409/422 (likely bad body/params, not auth)            | MEDIUM           |
| ROUTING_ERROR                   | 404/405                                                    | MEDIUM           |
| SERVER_ERROR                    | 5xx                                                        | MEDIUM           |
| UNKNOWN                         | Everything else                                            | LOW              |

---

## 📥 Installation

1. **Install Jython**  
   - Download `jython-standalone-2.7.x.jar`.  
   - In Burp → `Extender → Options → Python Environment` → Select the JAR.
2. **Load Extension**  
   - Save `broken_auth_analyzer.py`.  
   - In Burp → `Extender → Extensions → Add`:
     - Extension type: **Python**
     - Extension file: `broken_auth_analyzer.py`
3. **Verify**  
   - A **BrokenAuth Analyzer** tab appears with **Summary / Dashboard / Settings**.

---

## 📚 Usage Scenarios

- **Live Proxy Triage**  
  Browse the target; Auto Scan mutates in real time. Use **Summary → roll-up** to spot endpoints at risk fast.
- **Repeater What-Ifs**  
  Manually craft a baseline in Repeater, then **Send to BrokenAuth Analyzer** to see Removed/Stripped side-by-side.
- **Executive Snapshot**  
  Toggle roll-up, add **Notes**, then **Save CSV/JSON** for your findings log or ML pipeline.

---

## 🧱 Duplicate Suppression

A mutation is **skipped** only if all match an existing row: protocol, host, port, **method**, URL, mutation **mode**, normalized header set, and **body checksum**.  
Different methods for the same path are **always scanned**.

---

## 🧊 Static vs Dynamic

Treated as **static** (eligible for `NOT_VULNERABLE_STATIC`) when **GET** and:
- URL ends with a known static extension (`.js, .css, .png, .jpg, .ico, .svg, .woff, .woff2, .map, …`), **or**
- `Content-Type` starts with `image/*`, `text/css`, or `*javascript`.

Never static for server-side extensions: `.php, .asp, .aspx, .jsp, .do, .action, .cfm, .cgi, .pl, .rb, .py, .go`.

---

## 🪪 Requirements

- Burp Suite (Community or Pro)
- Jython 2.7.x
- Network access to target

_No external pip packages required._

---

## 👤 Author

**Narendra Reddy (Entersoft Security)**
