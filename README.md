# PHISHGUARD
//Phishing URL Detection System # Desktop Edition - Tkinter
import tkinter as tk
from tkinter import ttk, messagebox
import re
import ipaddress
from urllib.parse import urlparse, unquote


# ==========================================
# PHISHGUARD | Phishing URL Detection System
# Desktop Edition - Tkinter
# ==========================================


# ---------- DETECTION ENGINE ----------

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification",
    "password", "account", "secure", "update",
    "confirm", "banking", "wallet", "payment",
    "authenticate", "credential"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "click",
    "work", "gq", "tk", "ml", "cf"
}


def analyze_url(raw_url):

    score = 0
    findings = []

    # Normalize URL
    url = raw_url.strip()

    if not url:
        return None

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname or not parsed.netloc:
            return {
                "valid": False,
                "message": "Invalid URL structure"
            }

        hostname = hostname.lower()
        decoded_url = unquote(url).lower()

    except ValueError:
        return {
            "valid": False,
            "message": "Invalid URL format"
        }

    # 1. URL length
    if len(url) > 100:
        score += 10
        findings.append("Unusually long URL")

    # 2. IP address instead of domain
    try:
        ipaddress.ip_address(hostname)

        score += 25

        findings.append(
            "IP address used instead of domain name"
        )

    except ValueError:
        pass

    # 3. HTTPS check
    if parsed.scheme.lower() != "https":

        score += 10

        findings.append(
            "HTTPS encryption is not used"
        )

    # 4. @ symbol
    if "@" in parsed.netloc:

        score += 25

        findings.append(
            "Potential URL user-info deception"
        )

    # 5. Punycode detection
    if "xn--" in hostname:

        score += 20

        findings.append(
            "Internationalized domain / Punycode detected"
        )

    # 6. Subdomain analysis
    labels = hostname.split(".")

    if len(labels) >= 5:

        score += 15

        findings.append(
            "Excessive number of subdomains"
        )

    # 7. Hyphen detection
    if hostname.count("-") >= 3:

        score += 10

        findings.append(
            "Multiple hyphens in domain name"
        )

    # 8. Suspicious keywords
    matched_words = [
        word
        for word in SUSPICIOUS_WORDS
        if re.search(
            rf"(?<![a-z]){re.escape(word)}(?![a-z])",
            decoded_url
        )
    ]

    if matched_words:

        score += min(
            20,
            len(matched_words) * 5
        )

        findings.append(
            "Suspicious keywords: "
            + ", ".join(matched_words)
        )

    # 9. URL shortener
    if hostname in SHORTENERS:

        score += 20

        findings.append(
            "URL shortening service detected"
        )

    # 10. Suspicious top-level domain
    tld = labels[-1] if labels else ""

    if tld in SUSPICIOUS_TLDS:

        score += 15

        findings.append(
            "Potentially risky top-level domain"
        )

    # 11. Unusual port
    try:

        port = parsed.port

        if port is not None and port not in (80, 443):

            score += 10

            findings.append(
                "Non-standard port detected"
            )

    except ValueError:

        return {
            "valid": False,
            "message": "Invalid port number"
        }

    # Final score
    score = min(score, 100)

    if score >= 60:

        level = "HIGH RISK"
        status = "Potentially Malicious"

    elif score >= 30:

        level = "MEDIUM RISK"
        status = "Suspicious URL"

    else:

        level = "LOW RISK"
        status = "No major indicators detected"
        return {
        "valid": True,
        "url": url,
        "hostname": hostname,
        "score": score,
        "level": level,
        "status": status,
        "findings": findings
    }


# ==========================================
# APPLICATION COLORS
# ==========================================

BG = "#0b1220"
CARD = "#192940"
CARD_DARK = "#0f172a"
BORDER = "#30445f"

BLUE = "#38bdf8"
WHITE = "#ffffff"
MUTED = "#a8b8cc"

GREEN = "#22c55e"
YELLOW = "#facc15"
RED = "#ef4444"


# ==========================================
# MAIN WINDOW
# ==========================================

root = tk.Tk()

root.title(
    "PHISHGUARD | URL Security"
)

root.geometry("900x760")

root.minsize(
    700,
    620
)

root.configure(
    bg=BG
)


# ==========================================
# HEADER
# ==========================================

header = tk.Frame(
    root,
    bg=BG
)

header.pack(
    fill="x",
    padx=30,
    pady=(22, 18)
)


tk.Label(
    header,
    text="🛡️ PHISHGUARD",
    font=("Segoe UI", 30, "bold"),
    fg=BLUE,
    bg=BG
).pack()


tk.Label(
    header,
    text="Intelligent Phishing URL Detection System",
    font=("Segoe UI", 11),
    fg=MUTED,
    bg=BG
).pack(
    pady=(5, 0)
)


# ==========================================
# SCANNER CARD
# ==========================================

scanner = tk.Frame(
    root,
    bg=CARD,
    highlightbackground=BORDER,
    highlightthickness=1
)

scanner.pack(
    fill="x",
    padx=35,
    pady=(0, 15)
)


tk.Label(
    scanner,
    text="🔍 URL Security Scanner",
    font=("Segoe UI", 16, "bold"),
    fg=WHITE,
    bg=CARD
).pack(
    anchor="w",
    padx=20,
    pady=(18, 5)
)


tk.Label(
    scanner,
    text=(
        "Enter a URL to analyze its structure "
        "and detect potential phishing indicators."
    ),
    font=("Segoe UI", 10),
    fg=MUTED,
    bg=CARD,
    wraplength=780,
    justify="left"
).pack(
    anchor="w",
    padx=20,
    pady=(0, 14)
)


# ==========================================
# URL INPUT
# ==========================================

url_entry = tk.Entry(
    scanner,
    font=("Segoe UI", 12),
    bg=CARD_DARK,
    fg=WHITE,
    insertbackground=WHITE,
    relief="flat",
    highlightbackground=BORDER,
    highlightcolor=BLUE,
    highlightthickness=1
)

url_entry.pack(
    fill="x",
    padx=20,
    ipady=11
)

url_entry.insert(
    0,
    "https://example.com/login"
)


# ==========================================
# RESULTS CARD
# ==========================================

result_frame = tk.Frame(
    root,
    bg=CARD,
    highlightbackground=BORDER,
    highlightthickness=1
)

result_frame.pack(
    fill="both",
    expand=True,
    padx=35,
    pady=(0, 12)
)


# ==========================================
# CLEAR RESULTS
# ==========================================

def clear_results():

    for widget in result_frame.winfo_children():

        widget.destroy()


# ==========================================
# METRIC COMPONENT
# ==========================================

def create_metric(
    parent,
    title,
    value,
    color
):

    box = tk.Frame(
        parent,
        bg=CARD_DARK,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    box.pack(
        side="left",
        fill="both",
        expand=True,
        padx=5
    )

    tk.Label(
        box,
        text=title,
        font=("Segoe UI", 9, "bold"),
        fg=MUTED,
        bg=CARD_DARK
    ).pack(
        pady=(12, 5)
    )

    tk.Label(
        box,
        text=value,
        font=("Segoe UI", 13, "bold"),
        fg=color,
        bg=CARD_DARK,
        wraplength=220
    ).pack(
        padx=5,
        pady=(0, 12)
    )


# ==========================================
# ANALYZE URL
# ==========================================

def analyze_button_click():

    raw_url = url_entry.get().strip()

    # Empty input
    if not raw_url:

        messagebox.showwarning(
            "PHISHGUARD",
            "Please enter a URL first."
        )

        url_entry.focus_set()

        return
    # Analyze URL
    result = analyze_url(raw_url)

    # Invalid URL
    if not result or not result["valid"]:

        messagebox.showerror(
            "Invalid URL",
            result["message"]
            if result
            else "Invalid URL"
        )

        return

    # Clear previous results
    clear_results()

    # Get information
    score = result["score"]

    # Risk colors
    if score >= 60:

        risk_color = RED
        icon = "🚨"

    elif score >= 30:

        risk_color = YELLOW
        icon = "⚠️"

    else:

        risk_color = GREEN
        icon = "✅"

    # ======================================
    # RESULT TITLE
    # ======================================

    tk.Label(
        result_frame,
        text="📊 ANALYSIS RESULTS",
        font=("Segoe UI", 16, "bold"),
        fg=BLUE,
        bg=CARD
    ).pack(
        anchor="w",
        padx=20,
        pady=(16, 10)
    )

    # ======================================
    # METRICS
    # ======================================

    metrics = tk.Frame(
        result_frame,
        bg=CARD
    )

    metrics.pack(
        fill="x",
        padx=15,
        pady=5
    )

    create_metric(
        metrics,
        "RISK SCORE",
        f"{score}/100",
        risk_color
    )

    create_metric(
        metrics,
        "RISK LEVEL",
        result["level"],
        risk_color
    )

    create_metric(
        metrics,
        "DOMAIN",
        result["hostname"],
        WHITE
    )

    # ======================================
    # PROGRESS BAR
    # ======================================

    style = ttk.Style()

    style.theme_use("clam")

    style.configure(
        "Risk.Horizontal.TProgressbar",
        troughcolor=CARD_DARK,
        background=risk_color,
        bordercolor=BORDER,
        lightcolor=risk_color,
        darkcolor=risk_color
    )

    progress = ttk.Progressbar(
        result_frame,
        style="Risk.Horizontal.TProgressbar",
        maximum=100,
        value=score
    )

    progress.pack(
        fill="x",
        padx=22,
        pady=(12, 8)
    )

    # ======================================
    # STATUS
    # ======================================

    tk.Label(
        result_frame,
        text=f"{icon} {result['status']}",
        font=("Segoe UI", 14, "bold"),
        fg=risk_color,
        bg=CARD
    ).pack(
        anchor="w",
        padx=20,
        pady=8
    )

    # ======================================
    # DETECTION DETAILS
    # ======================================

    tk.Label(
        result_frame,
        text="🧠 Detection Details",
        font=("Segoe UI", 12, "bold"),
        fg=WHITE,
        bg=CARD
    ).pack(
        anchor="w",
        padx=20,
        pady=(8, 5)
    )

    findings = result["findings"]

    if findings:

        for finding in findings:

            tk.Label(
                result_frame,
                text=f"⚠️ {finding}",
                font=("Segoe UI", 10),
                fg=MUTED,
                bg=CARD,
                wraplength=780,
                justify="left"
            ).pack(
                anchor="w",
                padx=25,
                pady=2
            )

    else:

        tk.Label(
            result_frame,
            text=(
                "No major suspicious indicators "
                "were detected."
            ),
            font=("Segoe UI", 10),
            fg=GREEN,
            bg=CARD,
            wraplength=780,
            justify="left"
        ).pack(
            anchor="w",
            padx=25,
            pady=3
        )

    # ======================================
    # DISCLAIMER
    # ======================================

    tk.Label(
        result_frame,
        text=(
            "Note: This is a heuristic analysis, "
            "not a definitive security verdict. "
            "A low score does not guarantee that "
            "a URL is safe."
        ),
        font=("Segoe UI", 9),
        fg=MUTED,
        bg=CARD,
        wraplength=780,
        justify="left"
    ).pack(
        anchor="w",
        padx=20,
        pady=(12, 16)
    )


# ==========================================
# ANALYZE BUTTON
# ==========================================

analyze_button = tk.Button(
    scanner,
    text="🔍 ANALYZE URL",
    command=analyze_button_click,
    font=("Segoe UI", 12, "bold"),
    bg="#0284c7",
    fg=WHITE,
    activebackground="#0369a1",
    activeforeground=WHITE,
    relief="flat",
    cursor="hand2"
)

analyze_button.pack(
    fill="x",
    padx=20,
    pady=18,
    ipady=7
)


# ==========================================
# ENTER KEY SUPPORT
# ==========================================

url_entry.bind(
    "<Return>",
    lambda event: analyze_button_click()
)


# ==========================================
# FOOTER
# ==========================================

tk.Label(
    root,
    text=(
        "PHISHGUARD | Cyber Security Project | "
        "URL-Based Phishing Detection"
    ),
    font=("Segoe UI", 9),
    fg=MUTED,
    bg=BG
).pack(
    pady=(0, 12)
)


# ==========================================
# START APPLICATION
# ==========================================

url_entry.focus_set()

root.mainloop()
