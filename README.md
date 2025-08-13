# BrokenAuth Analyzer (Burp Suite Extension)

**BrokenAuth Analyzer** is a Burp Suite extension that automates **broken authentication** checks at scale by mutating only the **session-bearing headers** in live traffic and analyzing the server’s behavior with intelligent signals.

It’s built for pentesters who want fast, reliable signal with minimal noise — and for leads who need an at-a-glance roll-up of risk by endpoint and method.

---

## ✨ Key Capabilities

- **Two targeted mutations** (per request, per method):
  - **Removed All Session Headers** (drops only headers that look like session/identity)
  - **Stripped All Session Headers** (keeps the header names but empties their values)
- **Per-method coverage**: GET/POST/DELETE for the same path are tested **independently**.
- **De-dupe that respects reality**: suppresses *exact* duplicates only (proto/host/port + method + URL + mode + normalized header set + body checksum).
- **Intelligent verdicts & signals**:
  - Verdicts: `VULNERABLE`, `AUTH_ENFORCED`, `INPUT_ERROR`, `ROUTING_ERROR`, `SERVER_ERROR`, `NOT_VULNERABLE_EXPECTED_2XX`, `NOT_VULNERABLE_STATIC`, `AT_RISK` (roll-up), `UNKNOWN`
  - Signals: **Delta Size**, **Body Similarity**, **Header Diff** (chip + tooltip), content type, status code
- **Static noise reduction**: common static assets (e.g., `.js, .css, .png, .woff*`) and `image/*`, `text/css`, `*javascript` CTs are treated as **NOT_VULNERABLE_STATIC** when 2xx.
  - Never auto-classifies server-side extensions (.php/.asp/.jsp/.do/.action/…) as static.
- **UI built for triage**:
  - **Summary**: Metrics, Status Code Summary, and **Insights** table (with roll-up by URL+Method)
  - **Dashboard**: Row-level results with inline Request/Response **and a “Resend Selected”** button
  - **Settings**: Session header grid, custom headers, select all/none, **Auto Scan (Proxy & Repeater)**
- **One-click data capture for training**:
  - **Save CSV** → `brokenauth_insights.csv` (append)
  - **Save JSON** → `brokenauth_insights.jsonl` (append)
  - Files are written **next to the .py** (fallback: CWD → user home)

---

## 🧠 How it Works

1. For each request containing **selected session headers** (case-insensitive match; defaults include `Authorization`, `Cookie`, `X-*Token`, `X-Session-*`, etc.), the extension:
   - Builds two mutated requests: **Removed** and **Stripped**.
   - Sends them and compares responses against the baseline.
2. It computes:
   - **Delta Size** = `len(mutated_response_bytes) − len(baseline_response_bytes)`
   - **Similarity** (Jaccard over alphanumeric tokens; 0–100%)
   - **Header Diff**:
     - `+` Added headers, `-` Removed, `~` Changed (tooltip shows full before/after)
3. It classifies the mutated outcome into a **verdict** with a confidence score and surfaces all signals in **Insights**.

> Tip: “2xx + High Similarity + Small Delta + innocuous Header Diff” is a strong broken-auth signal.  
> “2xx + Low Similarity + Big Delta + `+WWW-Authenticate` absent” often indicates an error page with HTTP 200.

---

## 🖥️ UI Overview

### Summary
- **Metrics**: Project base URL, #Tested (unique method+path), count of 2xx
- **Status Code Summary**: Histogram by status
- **Insights** (sortable table):
  - Columns: `URL | Mode | Verdict | Severity | Confidence | Baseline | Mutated | Delta Size | Similarity | Header Diff | Signals | Notes`
  - **Roll-up toggle**: **“Group by URL+Method (roll-up)”** shows one line per (method, URL) with a combined verdict (`AT_RISK` if any mutated 2xx indicates bypass)
  - **Notes**: free-text, editable; included in exports
  - **Save CSV / Save JSON**: one click, appends to default files beside the script

### Dashboard
- Results table (row color: red = VULNERABLE, green = SAFE)
- Inline **Request / Response** viewers
- **Resend Selected** button (quick manual validation)

### Settings
- Checkboxes grid of **session headers** to target
- Add **custom header**, Select All/None
- **Enable Auto Scan for Proxy & Repeater** (listens to both tools)
- **Apply Header Settings** (updates selection)

---

## 🧩 Verdicts & Severity

| Verdict                         | What it means                                              | Default Severity |
|---------------------------------|------------------------------------------------------------|------------------|
| VULNERABLE                      | Mutated 2xx on non-static → likely auth bypass            | HIGH             |
| AT_RISK (roll-up)               | Any mutation suggests bypass for that URL+method          | HIGH             |
| AUTH_ENFORCED                   | 401/403                                                    | LOW              |
| NOT_VULNERABLE_EXPECTED_2XX     | 2xx where session wasn’t required (e.g., public endpoints)| LOW              |
| NOT_VULNERABLE_STATIC           | 2xx static content (GET + static ext/CT)                  | LOW              |
| INPUT_ERROR                     | 400/409/422 (likely bad body/params, not auth)            | MEDIUM           |
| ROUTING_ERROR                   | 404/405                                                    | MEDIUM           |
| SERVER_ERROR                    | 5xx                                                        | MEDIUM           |
| UNKNOWN                         | Everything else                                            | LOW              |

---

## 🔧 Installation

1. **Burp Suite** (Community or Pro)
2. **Jython 2.7.x**
3. Download `broken_auth_analyzer.py`
4. In Burp: `Extender → Extensions → Add`
   - **Extension type**: Python
   - **Extension file**: `broken_auth_analyzer.py`

---

## ▶️ Usage

- **Auto Mode**: Settings → check **Enable Auto Scan for Proxy & Repeater**. The extension will mutate qualifying requests seen by Proxy and Repeater.
- **Manual Mode**: Right-click any request → **Send to BrokenAuth Analyzer**.
- **Triaging**:
  - Use **Dashboard** to inspect specific rows; **Resend Selected** if needed.
  - Use **Summary → Insights** for a big-picture view; toggle **roll-up** to group by URL+Method.
  - Add **Notes** as you confirm/triage; then click **Save CSV / Save JSON** to log the Insights state to disk.

---

## 🧮 Exports (for ML/analytics)

- **CSV** → `brokenauth_insights.csv` (append)
- **JSON Lines** → `brokenauth_insights.jsonl` (append)

**Columns/Fields** (both formats share the same keys):
```
URL, Mode, Verdict, Severity, Confidence, Baseline, Mutated,
Delta Size, Similarity, Header Diff, Signals, Notes
```

> Files are saved next to `broken_auth_analyzer.py`. If that’s not writable, we fall back to CWD, then to the user’s home.

---

## 🧱 Duplicate Suppression

A mutated run is **skipped** only if all of the following match an existing row:
- protocol, host, port
- **method**
- URL
- mutation **mode** (Removed / Stripped)
- normalized header set (lowercased, sorted)
- **body checksum** (light byte sum)

This ensures:
- **Different methods** for the same path are **always scanned**.
- Exact replays of identical inputs don’t spam the dashboard.

---

## 🧊 Static vs Dynamic

- Treated as **static** (eligible for `NOT_VULNERABLE_STATIC`) when:
  - Method is **GET**, and
  - URL ends with a common static ext (`.js, .css, .png, .jpg, .ico, .svg, .woff*…`) **or**
  - `Content-Type` starts with `image/*`, `text/css`, or `*javascript`.
- **Never** marked static for server-side extensions: `.php, .asp, .aspx, .jsp, .do, .action, .cfm, .cgi, .pl, .rb, .py, .go…`.

---

## 🧭 Tips & Tactics

- **Header Diff**: look for `~Set-Cookie`, `+WWW-Authenticate`, or cache/CT flips.
- **Delta Size ~ 0** & **Similarity ≥ 90%** with 2xx → strong bypass indicator for sensitive endpoints.
- **INPUT_ERROR** on 4xx doesn’t clear auth — validate with a correct body to confirm behavior.

---

## 🪪 Requirements

- Burp Suite (Pro/Community)
- Jython 2.7.x

---

## 🧰 Troubleshooting

- **No rows for some methods?**  
  Ensure those requests actually include **selected session headers**. The tool mutates only headers **present** in the original request.

- **Save buttons do nothing?**  
  Check write permissions for the script’s folder. The extension falls back to CWD, then to user home.

- **CSV encoding issues on Windows?**  
  We write **UTF-8** via `codecs.open(…, "utf-8")`. Open with an editor that supports UTF-8 or import into a spreadsheet by specifying UTF-8.

---

## 🔒 Legal

Use only with **explicit authorization**. You are responsible for complying with all applicable laws and agreements.

---

## 👤 Author

**Narendra Reddy (Entersoft Security)**

Contributions & feedback welcome.
