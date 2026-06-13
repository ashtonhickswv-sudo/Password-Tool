#!/usr/bin/env python3
"""
password_tool.py
================
A password strength analyzer and secure password generator.

Features:
  - Analyses password strength across multiple criteria
  - Detects common/weak passwords via a built-in blocklist
  - Estimates time-to-crack using realistic attack speeds
  - Generates cryptographically secure passwords or passphrases
  - Colour-coded terminal output with detailed feedback
  - Optional CSV logging of analysis results (no plaintext passwords stored)

Usage:
  python password_tool.py --analyze
  python password_tool.py --generate --length 20 --symbols
  python password_tool.py --generate --passphrase --words 5
  python password_tool.py --analyze --log results.csv

Requirements:
  Python 3.8+ (standard library only)

Author: github.com/<your-handle>
License: MIT
"""

import argparse
import csv
import math
import re
import secrets
import string
import sys
from datetime import datetime
from getpass import getpass

# ─── ANSI colours ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"


# ─── Common weak passwords blocklist ──────────────────────────────────────────
WEAK_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football",
    "password1", "password123", "admin", "welcome", "login", "hello",
    "charlie", "donald", "password2", "qwerty123", "iloveyou1",
}

# ─── Wordlist for passphrase generation ───────────────────────────────────────
WORD_LIST = [
    "apple", "bridge", "castle", "dragon", "eagle", "forest", "garden",
    "harbor", "island", "jungle", "kitten", "lemon", "mountain", "ninja",
    "ocean", "pepper", "quartz", "river", "silver", "tiger", "umbrella",
    "violet", "walnut", "xenon", "yellow", "zephyr", "anchor", "blizzard",
    "circuit", "dagger", "ember", "falcon", "glacier", "horizon", "inferno",
    "jackal", "kestrel", "lantern", "marble", "nebula", "obsidian", "phantom",
    "quantum", "raven", "storm", "thunder", "ultra", "vortex", "whisper",
    "xylem", "yonder", "zenith", "amber", "bronze", "cobalt", "diesel",
    "eclipse", "frostbite", "granite", "hollow", "ignite", "javelin",
]


# ─── Strength analysis ────────────────────────────────────────────────────────
def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy in bits based on character pool size."""
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d",    password): pool += 10
    if re.search(r"[^a-zA-Z\d]", password): pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def crack_time_label(entropy: float) -> tuple[str, str]:
    """
    Estimate crack time assuming 10 billion guesses/second (modern GPU cluster).
    Returns (human-readable label, colour).
    """
    guesses = 2 ** entropy
    seconds = guesses / 10_000_000_000  # 10B guesses/sec

    if seconds < 1:
        return "Instantly", RED
    elif seconds < 60:
        return f"{seconds:.1f} seconds", RED
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes", RED
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours", YELLOW
    elif seconds < 2_592_000:
        return f"{seconds/86400:.1f} days", YELLOW
    elif seconds < 31_536_000:
        return f"{seconds/2_592_000:.1f} months", YELLOW
    elif seconds < 3_153_600_000:
        return f"{seconds/31_536_000:.1f} years", GREEN
    else:
        return f"{seconds/31_536_000:,.0f}+ years", GREEN


def score_password(password: str) -> dict:
    """
    Run the password through multiple checks and return a detailed report dict.
    Score: 0 (very weak) → 5 (very strong)
    """
    report = {
        "length":         len(password),
        "entropy":        round(calculate_entropy(password), 1),
        "has_lower":      bool(re.search(r"[a-z]", password)),
        "has_upper":      bool(re.search(r"[A-Z]", password)),
        "has_digit":      bool(re.search(r"\d", password)),
        "has_symbol":     bool(re.search(r"[^a-zA-Z\d]", password)),
        "is_common":      password.lower() in WEAK_PASSWORDS,
        "has_repeats":    bool(re.search(r"(.)\1{2,}", password)),
        "has_sequences":  bool(re.search(r"(012|123|234|345|456|567|678|789|"
                                         r"abc|bcd|cde|def|efg|qwe|asd|zxc)", password.lower())),
        "suggestions":    [],
    }

    # Scoring
    score = 0
    if report["length"] >= 8:  score += 1
    if report["length"] >= 12: score += 1
    if sum([report["has_lower"], report["has_upper"],
            report["has_digit"], report["has_symbol"]]) >= 3:
        score += 1
    if report["entropy"] >= 50: score += 1
    if not report["is_common"] and not report["has_repeats"] and not report["has_sequences"]:
        score += 1

    # Deductions
    if report["is_common"]:      score = max(0, score - 2)
    if report["has_repeats"]:    score = max(0, score - 1)
    if report["has_sequences"]:  score = max(0, score - 1)

    report["score"] = min(score, 5)

    # Human label
    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very Strong"}
    colours = {0: RED, 1: RED, 2: YELLOW, 3: YELLOW, 4: GREEN, 5: GREEN}
    report["label"]  = labels[report["score"]]
    report["colour"] = colours[report["score"]]

    crack, crack_colour = crack_time_label(report["entropy"])
    report["crack_time"]        = crack
    report["crack_time_colour"] = crack_colour

    # Suggestions
    if report["is_common"]:
        report["suggestions"].append("This is a well-known password — change it immediately.")
    if report["length"] < 12:
        report["suggestions"].append("Use at least 12 characters.")
    if not report["has_upper"]:
        report["suggestions"].append("Add uppercase letters (A-Z).")
    if not report["has_digit"]:
        report["suggestions"].append("Add numbers (0-9).")
    if not report["has_symbol"]:
        report["suggestions"].append("Add symbols (!, @, #, $, …).")
    if report["has_repeats"]:
        report["suggestions"].append("Avoid repeated characters (aaa, 111).")
    if report["has_sequences"]:
        report["suggestions"].append("Avoid sequential patterns (123, abc, qwerty).")

    return report


def print_analysis(report: dict, password: str) -> None:
    print()
    print(c("─" * 48, CYAN))
    print(c("  PASSWORD ANALYSIS REPORT", BOLD))
    print(c("─" * 48, CYAN))

    # Redact password in output — never echo it back in plaintext
    print(f"  Password   : {'*' * len(password)}")
    print(f"  Length     : {report['length']} characters")
    print(f"  Entropy    : {report['entropy']} bits")
    print(f"  Crack time : {c(report['crack_time'], report['crack_time_colour'])}")
    print()

    checks = [
        ("Lowercase letters", report["has_lower"]),
        ("Uppercase letters", report["has_upper"]),
        ("Numbers",           report["has_digit"]),
        ("Symbols",           report["has_symbol"]),
        ("Not a common pw",  not report["is_common"]),
        ("No repeat chars",  not report["has_repeats"]),
        ("No sequences",     not report["has_sequences"]),
    ]
    for label, passed in checks:
        icon   = c("✔", GREEN) if passed else c("✘", RED)
        colour = GREEN if passed else RED
        print(f"  {icon}  {c(label, colour)}")

    print()
    strength_bar = "█" * report["score"] + "░" * (5 - report["score"])
    print(f"  Strength   : {c(strength_bar, report['colour'])}  {c(report['label'], report['colour'])}")

    if report["suggestions"]:
        print()
        print(c("  Suggestions:", YELLOW))
        for s in report["suggestions"]:
            print(f"    • {s}")

    print(c("─" * 48, CYAN))
    print()


# ─── Password / passphrase generation ────────────────────────────────────────
def generate_password(length: int, use_symbols: bool, no_ambiguous: bool) -> str:
    """Generate a cryptographically secure random password."""
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if no_ambiguous:
        for ch in "Il1O0o":
            chars = chars.replace(ch, "")

    # Guarantee at least one of each required category
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if use_symbols:
        required.append(secrets.choice("!@#$%^&*()-_=+"))

    remaining = [secrets.choice(chars) for _ in range(length - len(required))]
    pool = required + remaining
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)


def generate_passphrase(word_count: int, separator: str) -> str:
    """Generate a memorable passphrase from random words + a random number."""
    words  = [secrets.choice(WORD_LIST) for _ in range(word_count)]
    number = secrets.randbelow(9000) + 1000          # 4-digit number
    words.append(str(number))
    secrets.SystemRandom().shuffle(words)
    return separator.join(words)


def print_generated(password: str, label: str = "Generated") -> None:
    report = score_password(password)
    print()
    print(c("─" * 48, CYAN))
    print(c(f"  {label.upper()}", BOLD))
    print(c("─" * 48, CYAN))
    print(f"  {c(password, GREEN)}")
    print(f"  Strength : {c(report['label'], report['colour'])}")
    print(f"  Entropy  : {report['entropy']} bits")
    print(f"  Crack    : {c(report['crack_time'], report['crack_time_colour'])}")
    print(c("─" * 48, CYAN))
    print()


# ─── CSV logging ──────────────────────────────────────────────────────────────
def log_to_csv(report: dict, path: str) -> None:
    """Append a sanitised (no plaintext password) row to a CSV log file."""
    fieldnames = ["timestamp", "length", "entropy", "score", "label",
                  "crack_time", "is_common", "has_repeats", "has_sequences"]
    row = {
        "timestamp":     datetime.now().isoformat(),
        "length":        report["length"],
        "entropy":       report["entropy"],
        "score":         report["score"],
        "label":         report["label"],
        "crack_time":    report["crack_time"],
        "is_common":     report["is_common"],
        "has_repeats":   report["has_repeats"],
        "has_sequences": report["has_sequences"],
    }
    write_header = True
    try:
        with open(path, "r") as f:
            write_header = f.read(1) == ""
    except FileNotFoundError:
        pass

    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerow(row)
    print(c(f"  [+] Result logged to {path} (password NOT stored)", GREEN))


# ─── CLI entry point ──────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Password strength analyzer and secure generator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze",    action="store_true", help="Analyze a password's strength")
    mode.add_argument("--generate",   action="store_true", help="Generate a secure password")

    # Generate options
    parser.add_argument("--length",     type=int,  default=16,   help="Password length (default: 16)")
    parser.add_argument("--symbols",    action="store_true",      help="Include symbols")
    parser.add_argument("--no-ambiguous", action="store_true",    help="Exclude ambiguous chars (Il1O0)")
    parser.add_argument("--passphrase", action="store_true",      help="Generate a word passphrase instead")
    parser.add_argument("--words",      type=int,  default=4,    help="Words in passphrase (default: 4)")
    parser.add_argument("--separator",  type=str,  default="-",  help="Passphrase word separator (default: -)")
    parser.add_argument("--count",      type=int,  default=1,    help="How many passwords to generate")

    # Shared options
    parser.add_argument("--log",        type=str,  default=None, help="Log analysis results to CSV file")

    args = parser.parse_args()

    print(c("\n  🔐  Password Tool  —  github.com/<your-handle>", CYAN))

    if args.analyze:
        try:
            password = getpass("  Enter password to analyze: ")
        except KeyboardInterrupt:
            print("\n  Cancelled.")
            sys.exit(0)

        if not password:
            print(c("  [!] No password entered.", RED))
            sys.exit(1)

        report = score_password(password)
        print_analysis(report, password)

        if args.log:
            log_to_csv(report, args.log)

    elif args.generate:
        for i in range(args.count):
            if args.passphrase:
                pw    = generate_passphrase(args.words, args.separator)
                label = f"Passphrase {i+1}" if args.count > 1 else "Passphrase"
            else:
                pw    = generate_password(args.length, args.symbols, args.no_ambiguous)
                label = f"Password {i+1}" if args.count > 1 else "Password"
            print_generated(pw, label)


if __name__ == "__main__":
    main()
