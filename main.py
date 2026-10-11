#!/usr/bin/env python3
"""
SNAYZA-Phishing-Awareness
A defensive phishing-awareness terminal application.

Author: Snayza
Version: 1.0.0
Python: 3.10+
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, unquote

APP_NAME = "SNAYZA-Phishing-Awareness"
VERSION = "1.0.0"
AUTHOR = "Snayza"
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "rb.gy", "ow.ly",
}
SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account",
    "update", "password", "wallet", "signin", "confirm",
    "gift", "free", "urgent", "recover", "suspended", "billing",
}

RED, GREEN, YELLOW, CYAN, MAGENTA, BOLD, RESET = (
    "\033[91m", "\033[92m", "\033[93m", "\033[96m",
    "\033[95m", "\033[1m", "\033[0m"
)


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


def clear_screen() -> None:
    import os
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    input("\nPress Enter to continue...")


def print_header() -> None:
    print(color("=" * 64, CYAN))
    print(color("  SNAYZA | PHISHING AWARENESS", BOLD + CYAN))
    print(color(f"  Defensive Security Toolkit | v{VERSION} | Author: {AUTHOR}", MAGENTA))
    print(color("=" * 64, CYAN))


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ValueError("URL cannot be empty.")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("URL contains control characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    return value


def analyze_url(raw_url: str) -> dict:
    """Static heuristic analysis only. No DNS lookup or network request."""
    score = 0
    findings = []
    try:
        url = normalize_url(raw_url)
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs can be analyzed.")
        if not parts.hostname:
            raise ValueError("URL has no valid hostname.")
        _ = parts.port

        hostname = parts.hostname.rstrip(".").lower()
        host_ascii = hostname.encode("idna").decode("ascii")
        labels = host_ascii.split(".")

        if parts.username is not None or parts.password is not None:
            score += 25
            findings.append(("HIGH", "User information appears before the hostname."))

        if parts.scheme.lower() == "http":
            score += 10
            findings.append(("MEDIUM", "The URL uses HTTP rather than HTTPS."))

        try:
            ipaddress.ip_address(host_ascii)
            score += 25
            findings.append(("HIGH", "The hostname is an IP address instead of a domain."))
        except ValueError:
            pass

        if "xn--" in host_ascii:
            score += 20
            findings.append(("HIGH", "The domain contains an IDN/Punycode label."))

        if host_ascii in SHORTENERS:
            score += 15
            findings.append(("MEDIUM", "The domain belongs to a known URL shortener."))

        if len(labels) >= 5:
            score += 10
            findings.append(("MEDIUM", "The hostname has many subdomain labels."))

        if "-" in host_ascii:
            score += 5
            findings.append(("LOW", "The hostname contains hyphens; inspect it carefully."))

        if len(host_ascii) > 50:
            score += 10
            findings.append(("MEDIUM", "The hostname is unusually long."))

        decoded = unquote(f"{parts.path} {parts.query} {parts.fragment}").lower()
        matched = sorted(
            word for word in SUSPICIOUS_WORDS
            if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", decoded + " " + host_ascii)
        )
        if matched:
            score += min(20, 5 * len(matched))
            findings.append(("MEDIUM", "Potentially sensitive keywords: " + ", ".join(matched[:8]) + "."))

        if len(url) > 200:
            score += 5
            findings.append(("LOW", "The complete URL is unusually long."))

        score = min(score, 100)
        if score >= 50:
            risk, advice = "HIGH RISK", "Do not open it unless independently verified."
        elif score >= 25:
            risk, advice = "SUSPICIOUS", "Verify the domain using a trusted source."
        else:
            risk, advice = "LOW HEURISTIC RISK", "No major configured warning was detected."

        if not findings:
            findings.append(("INFO", "No configured heuristic warning was triggered."))

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input": raw_url,
            "normalized_url": url,
            "hostname": host_ascii,
            "score": score,
            "risk": risk,
            "advice": advice,
            "findings": [{"severity": s, "message": m} for s, m in findings],
            "network_access": False,
            "author": AUTHOR,
            "disclaimer": "Heuristic result only; it cannot prove a URL is safe or malicious.",
        }
    except (ValueError, UnicodeError) as exc:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input": raw_url,
            "error": str(exc),
            "network_access": False,
            "author": AUTHOR,
        }


def display_report(report: dict) -> None:
    print("\n" + color("-" * 56, CYAN))
    print(color("  SNAYZA URL ANALYSIS REPORT", BOLD + CYAN))
    print(color("-" * 56, CYAN))
    if "error" in report:
        print(color(f"Invalid URL: {report['error']}", RED))
        return

    print(f"Hostname : {report['hostname']}")
    print(f"Score    : {report['score']}/100")
    tone = RED if report["score"] >= 50 else YELLOW if report["score"] >= 25 else GREEN
    print(f"Risk     : {color(report['risk'], BOLD + tone)}")
    print(f"Advice   : {report['advice']}")
    print("\nFindings:")
    for item in report["findings"]:
        sev = item["severity"]
        sev_color = RED if sev == "HIGH" else YELLOW if sev == "MEDIUM" else CYAN
        print(f"  [{color(sev, sev_color)}] {item['message']}")
    print(f"\nNote: {report['disclaimer']}")
    print("Network requests: none")


def save_report(report: dict) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = REPORTS_DIR / f"snayza_report_{stamp}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


QUIZ = [
    {
        "question": "An email asks you to verify your account urgently. What is best?",
        "options": ["A) Click immediately", "B) Visit the official site independently",
                    "C) Reply with your password", "D) Forward it to everyone"],
        "answer": "B",
        "explanation": "Use a known official address or trusted app instead of an unexpected link.",
    },
    {
        "question": "What does HTTPS guarantee?",
        "options": ["A) The website is honest", "B) The website has no malware",
                    "C) The connection is encrypted, not that the site is trustworthy",
                    "D) The website belongs to a bank"],
        "answer": "C",
        "explanation": "HTTPS protects data in transit but does not prove the operator is legitimate.",
    },
    {
        "question": "A sender's address differs slightly from the real company. What should you do?",
        "options": ["A) Ignore the difference", "B) Verify through an independent channel",
                    "C) Download every attachment", "D) Share the message publicly"],
        "answer": "B",
        "explanation": "Lookalike domains and misleading sender details are common phishing indicators.",
    },
    {
        "question": "What is a safer way to handle an unexpected attachment?",
        "options": ["A) Open it to see what happens", "B) Disable security software",
                    "C) Verify the message with the sender through another channel",
                    "D) Enable all macros"],
        "answer": "C",
        "explanation": "Unexpected files should be verified before opening.",
    },
    {
        "question": "What should you do if you entered a password on a suspected phishing site?",
        "options": ["A) Reuse it elsewhere", "B) Change it through the official site and alert support",
                    "C) Wait and do nothing", "D) Send the password to the email sender"],
        "answer": "B",
        "explanation": "Change compromised credentials through the legitimate service and follow its incident process.",
    },
]


def run_quiz() -> None:
    score = 0
    print_header()
    print("\nPHISHING AWARENESS QUIZ\nChoose A, B, C or D.")
    for number, item in enumerate(QUIZ, start=1):
        print(f"\n{number}/{len(QUIZ)}. {item['question']}")
        for option in item["options"]:
            print("  " + option)
        while True:
            answer = input("Your answer: ").strip().upper()
            if answer in {"A", "B", "C", "D"}:
                break
            print("Please enter A, B, C or D.")
        if answer == item["answer"]:
            score += 1
            print(color("Correct!", GREEN))
        else:
            print(color(f"Incorrect. Correct answer: {item['answer']}", RED))
        print("Why:", item["explanation"])

    percent = round(score / len(QUIZ) * 100)
    print(f"\nFinal result: {score}/{len(QUIZ)} ({percent}%)")
    if percent >= 80:
        print(color("Excellent work! Keep checking unexpected messages.", GREEN))
    elif percent >= 60:
        print(color("Good start. Review the explanations and try again.", YELLOW))
    else:
        print(color("Review the awareness guide before retrying.", YELLOW))

    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path = REPORTS_DIR / "quiz_history.json"
        history = []
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                history = existing if isinstance(existing, list) else []
            except (json.JSONDecodeError, OSError):
                history = []
        history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": score, "total": len(QUIZ), "percentage": percent,
            "author": AUTHOR,
        })
        path.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Quiz history saved to: {path.relative_to(BASE_DIR)}")
    except OSError as exc:
        print(f"Could not save quiz history: {exc}")


def awareness_guide() -> None:
    print_header()
    print("""
PHISHING AWARENESS GUIDE
========================
1. CHECK THE SENDER
   Inspect the complete email address, not just the display name.

2. CHECK THE DOMAIN
   Watch for misspellings, lookalike characters, and strange subdomains.

3. BE CAUTIOUS WITH URGENCY
   Unexpected threats, prizes, invoices, or account warnings deserve
   independent verification.

4. DO NOT SHARE SECRETS
   Never disclose passwords or verification codes in response to an
   unexpected message.

5. HANDLE ATTACHMENTS CAREFULLY
   Verify unexpected files with the sender through a separate channel.

6. USE MULTI-FACTOR AUTHENTICATION
   Prefer phishing-resistant methods when available.

7. IF YOU SUSPECT PHISHING
   Stop interacting. Report the message through an approved channel.
   If credentials were entered, change them through the official service
   and contact its support team.

REMEMBER
A padlock, HTTPS, polished design, or familiar logo does not prove a
website is legitimate. When in doubt, verify independently.
""")


def show_examples() -> None:
    print_header()
    print("""
SAFE TRAINING EXAMPLES
======================
1. https://accounts.example.com
   Discuss whether the domain is the official service domain.
   example.com is reserved for documentation examples.

2. http://192.0.2.10/login
   Plain HTTP and an IP-based hostname are warning indicators.
   192.0.2.0/24 is reserved for documentation.

3. https://example.com@attacker.invalid/
   Text before @ is user information; the hostname is attacker.invalid.
   This is a demonstration, not a live target.

These examples are educational. No URLs are opened.
""")


def analyze_menu() -> None:
    print_header()
    print("\nURL SECURITY ANALYZER")
    print("Paste a URL for static analysis. The program will not visit it.")
    report = analyze_url(input("\nURL: ").strip())
    display_report(report)
    if "error" not in report and input("\nSave this report? (y/n): ").strip().lower() == "y":
        try:
            path = save_report(report)
            print(color(f"Saved: {path.relative_to(BASE_DIR)}", GREEN))
        except OSError as exc:
            print(color(f"Could not save report: {exc}", RED))
    pause()


def view_reports() -> None:
    print_header()
    print("\nSAVED URL REPORTS\n")
    if not REPORTS_DIR.exists():
        print("No reports found yet.")
        pause()
        return
    reports = sorted(REPORTS_DIR.glob("snayza_report_*.json"))
    if not reports:
        print("No URL reports found yet.")
    else:
        for index, path in enumerate(reports[-20:], start=1):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                summary = "Invalid URL" if "error" in data else (
                    f"{data.get('risk', 'Unknown')} | {data.get('hostname', 'Unknown')} | "
                    f"{data.get('score', '?')}/100"
                )
                print(f"{index:>2}. {path.name}\n    {summary}")
            except (OSError, json.JSONDecodeError):
                print(f"{index:>2}. {path.name} (could not read)")
    pause()


def main() -> None:
    while True:
        clear_screen()
        print_header()
        print("""
  [1] Analyze a URL
  [2] Phishing awareness quiz
  [3] Awareness guide
  [4] Safe training examples
  [5] View saved URL reports
  [0] Exit
""")
        choice = input("SNAYZA > ").strip()
        if choice == "1":
            analyze_menu()
        elif choice == "2":
            run_quiz()
            pause()
        elif choice == "3":
            awareness_guide()
            pause()
        elif choice == "4":
            show_examples()
            pause()
        elif choice == "5":
            view_reports()
        elif choice == "0":
            print(color("\nStay alert. Stay safe. | SNAYZA", CYAN))
            break
        else:
            print(color("Invalid choice. Select a menu option.", RED))
            pause()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nSNAYZA: Program closed.")
