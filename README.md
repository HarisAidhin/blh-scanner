# BLH Scanner

A mass scanner for detecting **Broken Link Hijacking (BLH)** on social media links embedded in web pages.
Outputs results to terminal, JSON (concise), and a clean dark-themed HTML report.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Maintained by **Haris Aidhin Ramadhan** ([@HarisAidhin](https://github.com/HarisAidhin)).

---

## Overview

Broken Link Hijacking occurs when a website still points to social media handles or domains that no longer exist. An attacker can register the expired handle/domain and gain control over the traffic.

This tool scans one or more target websites, extracts social media links, checks their status, and reports any that appear to be broken or claimable.

Supported platforms:

`twitter / x` · `facebook` · `instagram` · `linkedin` · `youtube` · `tiktok` · `github` · `telegram`

Facebook detection uses body fingerprinting (soft-404 markers) because Facebook often returns HTTP 200 for deleted pages.

---

## Installation

```bash
git clone https://github.com/HarisAidhinR/blh-scanner.git
cd blh-scanner
pip install -r requirements.txt
```

---

## Usage

**Scan a single target:**

```bash
python3 blh.py -u https://example.com
```

**Scan multiple targets:**

```bash
python3 blh.py -u https://a.com -u https://b.com
```

**Mass scan from file:**

```bash
python3 blh.py -l targets.txt
```

**Save results:**

```bash
python3 blh.py -l targets.txt \
  -o hasil.json \
  --html report.html
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-u, --url` | Target URL (repeatable) | - |
| `-l, --list` | File with one URL per line | - |
| `-o, --output` | Save concise JSON report | - |
| `--html` | Save dark-themed HTML report | - |
| `-t, --timeout` | Request timeout (seconds) | `15` |
| `-w, --workers` | Parallel workers per target | `5` |

---

## Output

### Terminal

Only vulnerable targets are shown. Each finding includes platform, URL, and reason.

```text
┌─ [1/3] https://site-a.com
│  ✗ 2 POTENSI BROKEN LINK HIJACKING
  [HIJACK]   TWITTER    https://twitter.com/oldhandle
      ↳ Profil twitter mengembalikan 404 (handle mungkin tersedia)
  [HIJACK]   FACEBOOK   https://facebook.com/oldpage
      ↳ Profil Facebook menampilkan 'content isn't available'
└─
```

### JSON (concise)

```json
{
  "total_targets": 3,
  "vulnerable_targets": 1,
  "total_findings": 2,
  "results": [
    {
      "target": "https://site-a.com",
      "vulnerable": [
        { "platform": "twitter", "url": "https://twitter.com/oldhandle" },
        { "platform": "facebook", "url": "https://facebook.com/oldpage" }
      ]
    }
  ]
}
```

### HTML Report

A self-contained dark-themed report (GitHub-Dark palette) with summary cards, platform breakdown, and per-target cards.
Open the generated `.html` file in any modern browser.

---

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**.
Use it only against assets you own or have explicit written permission to test.
The author is not responsible for any misuse or damage caused by this tool.

---

## License

[MIT](LICENSE) © Haris Aidhin Ramadhan
