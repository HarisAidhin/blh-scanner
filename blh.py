
"""
Broken Link Hijacking (BLH) Mass Scanner | By HarisAidhinR | - Social Media
Hanya menampilkan target yang RENTAN.

Contoh:
  python3 blh.py -u https://target.com
  python3 blh.py -l targets.txt -o hasil.json --html report.html
"""

import argparse
import html
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin

try:
    import requests
    from requests.exceptions import ConnectionError, Timeout, RequestException
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("[!] Install 'requests': pip install requests")
    sys.exit(1)


class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def log(msg, color=C.WHITE, bold=False):
    prefix = C.BOLD if bold else ""
    print(f"{prefix}{color}{msg}{C.RESET}")


SOCIAL_PATTERNS = {
    "twitter":   r"(?:twitter\.com|x\.com)/[\w]+",
    "facebook":  r"facebook\.com/[\w.]+",
    "instagram": r"instagram\.com/[\w.]+",
    "linkedin":  r"linkedin\.com/(?:in|company)/[\w-]+",
    "youtube":   r"youtube\.com/(?:c/|channel/|user/|@)[\w-]+",
    "tiktok":    r"tiktok\.com/@[\w.]+",
    "github":    r"github\.com/[\w-]+",
    "telegram":  r"(?:t\.me|telegram\.me)/[\w]+",
}


FACEBOOK_BROKEN_MARKERS = [
    "This content isn't available at the moment",
    "This content isn't available right now",
    "The link you followed may have expired",
    "Halaman ini tidak tersedia",
    "Konten ini tidak tersedia",
]


INSTAGRAM_BROKEN_MARKERS = [
    "Maaf, halaman ini tidak tersedia",
    "Tautan yang Anda ikuti mungkin rusak",
    "Sorry, this page isn't available",
    "The link you followed may be broken",
]

BROKEN_STATUS_CODES = {404, 410}
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}



def normalize_url(url: str) -> str:
    url = url.strip()
    if not url or url.startswith("#"):
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def extract_social_links(html_text: str, base_url: str) -> set:
    links = set()
    for match in re.finditer(r'(?:href|src)=["\']([^"\']+)', html_text, re.IGNORECASE):
        raw = match.group(1).strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        if raw.startswith(("http://", "https://")):
            full_url = raw
        elif raw.startswith("/"):
            full_url = urljoin(base_url, raw)
        else:
            continue
        for pattern in SOCIAL_PATTERNS.values():
            if re.search(pattern, full_url, re.IGNORECASE):
                links.add(full_url)
                break
    return links


def is_facebook_broken(url: str, body: str) -> bool:
    if not re.search(SOCIAL_PATTERNS["facebook"], url, re.IGNORECASE):
        return False
    lowered = body.lower()
    return any(m.lower() in lowered for m in FACEBOOK_BROKEN_MARKERS)


def is_instagram_broken(url: str, body: str) -> bool:
    if not re.search(SOCIAL_PATTERNS["instagram"], url, re.IGNORECASE):
        return False
    lowered = body.lower()
    return any(m.lower() in lowered for m in INSTAGRAM_BROKEN_MARKERS)


def check_link_status(url: str, timeout: int = 15) -> dict:
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            verify=False, headers=HEADERS)
        broken = resp.status_code in BROKEN_STATUS_CODES
        
        
        if not broken and resp.status_code == 200:
            if is_facebook_broken(url, resp.text) or is_instagram_broken(url, resp.text):
                broken = True
                
        return {"url": url, "status_code": resp.status_code, "broken": broken, "error": None}
    except ConnectionError:
        return {"url": url, "status_code": None, "broken": True, "error": "connection_failed"}
    except Timeout:
        return {"url": url, "status_code": None, "broken": False, "error": "timeout"}
    except RequestException as e:
        return {"url": url, "status_code": None, "broken": False, "error": str(e)[:120]}


def analyze_hijackability(info: dict) -> dict | None:
    if not info.get("broken"):
        return None
    url = info["url"]
    platform = next((n for n, p in SOCIAL_PATTERNS.items()
                     if re.search(p, url, re.IGNORECASE)), "unknown")

    if info.get("error") == "connection_failed":
        return {"url": url, "platform": platform, "risk": "CRITICAL", "status_code": None,
                "reason": "Domain tidak merespons (kemungkinan unregistered / expired)"}

    if platform == "facebook":
        reason = "Profil Facebook menampilkan 'content isn't available' (akun dihapus / dibatasi)"
    elif platform == "instagram":
        reason = "Profil Instagram menampilkan 'halaman ini tidak tersedia' (akun dihapus / dibatasi)"
    else:
        reason = f"Profil {platform} mengembalikan {info['status_code']} (handle mungkin tersedia)"

    return {"url": url, "platform": platform, "risk": "HIGH",
            "status_code": info["status_code"], "reason": reason}



def scan_target(target: str, timeout: int) -> dict:
    result = {"target": target, "status": "success",
              "total_social_links": 0, "findings": [], "error": None}
    try:
        resp = requests.get(target, timeout=timeout, verify=False, headers=HEADERS)
        resp.raise_for_status()
    except RequestException as e:
        result["status"] = "error"
        result["error"] = str(e)[:150]
        return result

    links = extract_social_links(resp.text, target)
    result["total_social_links"] = len(links)
    if not links:
        return result

    with ThreadPoolExecutor(max_workers=8) as pool:
        for fut in as_completed({pool.submit(check_link_status, l, timeout): l for l in links}):
            f = analyze_hijackability(fut.result())
            if f:
                result["findings"].append(f)
    return result



def print_finding(finding: dict):
    platform = finding["platform"].upper()
    risk = finding["risk"]
    url = finding["url"]
    if risk == "CRITICAL":
        risk_color, tag = C.MAGENTA + C.BOLD, "[CRITICAL]"
    else:
        risk_color, tag = C.RED + C.BOLD, "[HIJACK]"

    platform_colors = {
        "TWITTER": C.CYAN, "FACEBOOK": C.BLUE, "INSTAGRAM": C.MAGENTA,
        "LINKEDIN": C.BLUE, "YOUTUBE": C.RED, "TIKTOK": C.WHITE,
        "GITHUB": C.WHITE, "TELEGRAM": C.CYAN,
    }
    pcolor = platform_colors.get(platform, C.YELLOW)
    print(f"  {risk_color}{tag}{C.RESET} {pcolor}{platform:<10}{C.RESET} {C.RED}{url}{C.RESET}")
    print(f"      {C.DIM}↳ {finding['reason']}{C.RESET}")



HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BLH Report — Social Media ByHrsar</title>
<style>
:root {{
  --bg: #0d1117;
  --surface: #161b22;
  --surface-2: #1c2128;
  --border: #30363d;
  --border-soft: #21262d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --text-dim: #6e7681;
  --accent: #58a6ff;
  --critical: #f85149;
  --high: #d29922;
  --success: #3fb950;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{ background: var(--bg); color: var(--text); }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", sans-serif;
  font-size: 14px; line-height: 1.6; padding: 48px 24px;
  -webkit-font-smoothing: antialiased;
}}
.container {{ max-width: 1080px; margin: 0 auto; }}

/* Header */
header {{
  padding-bottom: 28px; margin-bottom: 32px;
  border-bottom: 1px solid var(--border);
}}
.header-top {{ display: flex; align-items: center; gap: 12px; }}
.logo-dot {{
  width: 10px; height: 10px; border-radius: 50%;
  background: var(--critical); box-shadow: 0 0 12px rgba(248, 81, 73, 0.5);
}}
h1 {{ font-size: 22px; font-weight: 600; letter-spacing: -0.01em; }}
.subtitle {{ color: var(--text-muted); font-size: 13px; margin-top: 8px; }}
.subtitle code {{
  font-family: var(--mono); font-size: 12px;
  background: var(--surface); padding: 2px 6px; border-radius: 4px;
  border: 1px solid var(--border-soft); color: var(--text);
}}

/* Summary Grid */
.summary {{
  display: grid; grid-template-columns: repeat(3, 1fr);
  gap: 12px; margin-bottom: 28px;
}}
.stat {{
  background: var(--surface); border: 1px solid var(--border-soft);
  border-radius: 8px; padding: 18px 20px;
}}
.stat-label {{
  color: var(--text-muted); font-size: 11px; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px;
}}
.stat-value {{
  font-size: 28px; font-weight: 600; font-family: var(--mono);
  letter-spacing: -0.02em;
}}
.stat-value.critical {{ color: var(--critical); }}
.stat-value.neutral {{ color: var(--text); }}

/* Platform Chips */
.chips {{
  display: flex; flex-wrap: wrap; gap: 8px;
  margin-bottom: 36px; padding-bottom: 28px;
  border-bottom: 1px solid var(--border-soft);
}}
.chip {{
  display: inline-flex; align-items: center; gap: 8px;
  background: var(--surface); border: 1px solid var(--border-soft);
  border-radius: 20px; padding: 5px 12px 5px 14px;
  font-size: 12px; color: var(--text-muted);
}}
.chip b {{
  font-family: var(--mono); font-size: 11px; font-weight: 600;
  color: var(--text); background: var(--surface-2);
  padding: 1px 7px; border-radius: 10px;
  border: 1px solid var(--border);
}}

/* Target Card */
.section-title {{
  font-size: 12px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--text-muted);
  margin-bottom: 16px;
}}
.target-card {{
  background: var(--surface); border: 1px solid var(--border-soft);
  border-radius: 10px; margin-bottom: 16px; overflow: hidden;
}}
.target-head {{
  display: flex; justify-content: space-between; align-items: center;
  padding: 16px 20px; border-bottom: 1px solid var(--border-soft);
  background: var(--surface-2);
}}
.target-url {{
  font-family: var(--mono); font-size: 13px; color: var(--text);
  font-weight: 500; word-break: break-all;
}}
.target-count {{
  font-size: 11px; font-weight: 500; color: var(--critical);
  background: rgba(248, 81, 73, 0.1); padding: 3px 10px;
  border-radius: 10px; border: 1px solid rgba(248, 81, 73, 0.25);
  white-space: nowrap; margin-left: 12px;
}}

/* Finding */
.finding {{ padding: 16px 20px; border-bottom: 1px solid var(--border-soft); }}
.finding:last-child {{ border-bottom: none; }}
.finding-head {{
  display: flex; align-items: center; gap: 8px; margin-bottom: 8px;
}}
.platform-badge {{
  font-family: var(--mono); font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.04em;
  padding: 2px 8px; border-radius: 4px;
  background: var(--surface-2); color: var(--text-muted);
  border: 1px solid var(--border);
}}
.risk-tag {{
  font-size: 10px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.06em; padding: 2px 8px; border-radius: 4px;
}}
.risk-tag.high {{
  color: var(--high); background: rgba(210, 153, 34, 0.1);
  border: 1px solid rgba(210, 153, 34, 0.3);
}}
.risk-tag.critical {{
  color: var(--critical); background: rgba(248, 81, 73, 0.1);
  border: 1px solid rgba(248, 81, 73, 0.3);
}}
.finding-url {{
  display: block; font-family: var(--mono); font-size: 13px;
  color: var(--accent); text-decoration: none;
  word-break: break-all; margin-bottom: 6px;
  transition: color 0.15s ease;
}}
.finding-url:hover {{ color: #79b8ff; text-decoration: underline; }}
.finding-reason {{
  font-size: 12.5px; color: var(--text-muted);
  padding-left: 12px; border-left: 2px solid var(--border);
}}

/* Empty state */
.empty {{
  text-align: center; padding: 60px 20px;
  color: var(--text-muted); font-size: 14px;
}}
.empty-icon {{ font-size: 32px; margin-bottom: 12px; opacity: 0.5; }}

/* Footer */
footer {{
  margin-top: 48px; padding-top: 24px;
  border-top: 1px solid var(--border-soft);
  color: var(--text-dim); font-size: 12px;
  text-align: center; font-family: var(--mono);
}}

@media (max-width: 640px) {{
  body {{ padding: 24px 16px; }}
  .summary {{ grid-template-columns: 1fr; }}
  .target-head {{ flex-direction: column; align-items: flex-start; gap: 8px; }}
  .target-count {{ margin-left: 0; }}
}}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-top">
      <span class="logo-dot"></span>
      <h1>Broken Link Hijacking Report</h1>
    </div>
    <p class="subtitle">
      Social Media Scan &middot; <code>{generated_at}</code> &middot; <code>{total_targets} target</code>
    </p>
  </header>

  <div class="summary">
    <div class="stat">
      <div class="stat-label">Target Dipindai</div>
      <div class="stat-value neutral">{total_targets}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Target Rentan</div>
      <div class="stat-value {vuln_class}">{vulnerable_count}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Total Temuan</div>
      <div class="stat-value {finding_class}">{total_findings}</div>
    </div>
  </div>

  {chips_html}

  <div class="section-title">Detail Temuan</div>
  {cards_html}
  {empty_html}

  <footer>Generated by Haris Aidhin Ramadhan</footer>
</div>
</body>
</html>
"""


def generate_html_report(results: list, total_targets: int, output_path: str):
    """Buat laporan HTML dark elegan."""
    vulnerable = [r for r in results if r["findings"]]
    total_findings = sum(len(r["findings"]) for r in vulnerable)
    vuln_count = len(vulnerable)

    # Platform breakdown
    platform_count = {}
    for r in vulnerable:
        for f in r["findings"]:
            platform_count[f["platform"]] = platform_count.get(f["platform"], 0) + 1

    chips_html = ""
    if platform_count:
        chips = "".join(
            f'<span class="chip">{html.escape(p)}<b>{c}</b></span>'
            for p, c in sorted(platform_count.items(), key=lambda x: -x[1])
        )
        chips_html = f'<div class="chips">{chips}</div>'

    # Target cards
    cards_html = ""
    for r in vulnerable:
        findings_html = ""
        for f in r["findings"]:
            risk_cls = "critical" if f["risk"] == "CRITICAL" else "high"
            url_safe = html.escape(f["url"])
            findings_html += f"""
            <div class="finding">
              <div class="finding-head">
                <span class="platform-badge">{html.escape(f['platform'])}</span>
                <span class="risk-tag {risk_cls}">{f['risk']}</span>
              </div>
              <a href="{url_safe}" target="_blank" rel="noopener" class="finding-url">{url_safe}</a>
              <div class="finding-reason">{html.escape(f['reason'])}</div>
            </div>"""

        cards_html += f"""
        <div class="target-card">
          <div class="target-head">
            <span class="target-url">{html.escape(r['target'])}</span>
            <span class="target-count">{len(r['findings'])} temuan</span>
          </div>
          {findings_html}
        </div>"""

    empty_html = ""
    if not vulnerable:
        empty_html = """
        <div class="empty">
          <div class="empty-icon">&#10003;</div>
          <div>Tidak ada broken link hijacking terdeteksi pada target.</div>
        </div>"""

    final = HTML_TEMPLATE.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_targets=total_targets,
        vulnerable_count=vuln_count,
        total_findings=total_findings,
        vuln_class="critical" if vuln_count else "neutral",
        finding_class="critical" if total_findings else "neutral",
        chips_html=chips_html,
        cards_html=cards_html,
        empty_html=empty_html,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(final)


# ============================================================
# MAIN
# ============================================================
def load_targets(args) -> list:
    targets = []
    if args.url:
        for u in args.url:
            n = normalize_url(u)
            if n:
                targets.append(n)
    if args.list:
        if not os.path.isfile(args.list):
            log(f"[!] File tidak ditemukan: {args.list}", C.RED)
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                n = normalize_url(line)
                if n:
                    targets.append(n)
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def main():
    parser = argparse.ArgumentParser(
        description="BLH Mass Scanner - Social Media (terminal + JSON + HTML)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Contoh:\n"
            "  python3 blh.py -u https://target.com\n"
            "  python3 blh.py -l targets.txt -o hasil.json\n"
            "  python3 blh.py -l targets.txt --html report.html\n"
            "  python3 blh.py -l targets.txt -o hasil.json --html report.html\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", action="append", metavar="URL", help="Target URL (bisa diulang)")
    group.add_argument("-l", "--list", metavar="FILE", help="File daftar target (1 URL per baris)")

    parser.add_argument("-o", "--output", metavar="FILE", help="Simpan hasil ke JSON (ringkas)")
    parser.add_argument("--html", metavar="FILE", help="Simpan hasil ke laporan HTML (dark elegan)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Timeout request (default: 15)")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Worker paralel (default: 5)")
    args = parser.parse_args()

    targets = load_targets(args)
    if not targets:
        log("[!] Tidak ada target valid.", C.RED)
        sys.exit(1)

    log("=" * 70, C.CYAN, bold=True)
    log("  BLH SCANNER - SOCIAL MEDIA By HRS", C.CYAN, bold=True)
    log(f"  Total target : {len(targets)}", C.WHITE)
    log(f"  Timeout      : {args.timeout}s", C.WHITE)
    log(f"  Workers      : {args.workers}", C.WHITE)
    if args.output:
        log(f"  JSON         : {args.output}", C.WHITE)
    if args.html:
        log(f"  HTML         : {args.html}", C.WHITE)
    log("=" * 70, C.CYAN, bold=True)

    all_results = []
    vulnerable_count = 0
    total_findings = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {pool.submit(scan_target, t, args.timeout): (i, t)
                      for i, t in enumerate(targets, 1)}
        for fut in as_completed(future_map):
            idx, target = future_map[fut]
            try:
                result = fut.result()
            except Exception as e:
                result = {"target": target, "status": "error", "error": str(e)[:150],
                          "findings": [], "total_social_links": 0}
            all_results.append(result)

            if result["findings"]:
                vulnerable_count += 1
                total_findings += len(result["findings"])
                print()
                log(f"┌─ [{idx}/{len(targets)}] {target}", C.RED, bold=True)
                log(f"│  ✗ {len(result['findings'])} POTENSI BROKEN LINK HIJACKING", C.RED, bold=True)
                for f in result["findings"]:
                    print_finding(f)
                log("└─", C.DIM)

    # Ringkasan
    print()
    log("=" * 70, C.CYAN, bold=True)
    log("  RINGKASAN (HANYA TARGET RENTAN)", C.CYAN, bold=True)
    log("=" * 70, C.CYAN, bold=True)
    log(f"  Total target dipindai : {len(targets)}", C.WHITE)
    log(f"  Target rentan         : {vulnerable_count}", C.RED if vulnerable_count else C.GREEN)
    log(f"  Total temuan BLH      : {total_findings}", C.RED if total_findings else C.GREEN)

    if total_findings:
        platform_count = {}
        for r in all_results:
            for f in r["findings"]:
                platform_count[f["platform"]] = platform_count.get(f["platform"], 0) + 1
        log("\n  Breakdown per platform:", C.YELLOW, bold=True)
        for plat, cnt in sorted(platform_count.items(), key=lambda x: -x[1]):
            log(f"    • {plat:<12} : {C.RED}{cnt}{C.RESET} broken link", C.WHITE)
    log("=" * 70, C.CYAN, bold=True)

    # Simpan JSON
    if args.output:
        vuln_results = [
            {"target": r["target"],
             "vulnerable": [{"platform": f["platform"], "url": f["url"]} for f in r["findings"]]}
            for r in all_results if r["findings"]
        ]
        summary = {
            "total_targets": len(targets),
            "vulnerable_targets": vulnerable_count,
            "total_findings": total_findings,
            "results": vuln_results,
        }
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            log(f"\n[*] JSON ringkas disimpan ke: {args.output}", C.GREEN, bold=True)
        except Exception as e:
            log(f"\n[!] Gagal simpan JSON: {e}", C.RED)

    # Simpan HTML
    if args.html:
        try:
            generate_html_report(all_results, len(targets), args.html)
            log(f"[*] Laporan HTML disimpan ke: {args.html}", C.GREEN, bold=True)
        except Exception as e:
            log(f"[!] Gagal simpan HTML: {e}", C.RED)


if __name__ == "__main__":
    main()
