#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Animated Password Strength Checker
Author: Karndeep Baror - Ethical Hacker 🇮🇳 
Terminal Based Password Strength Checker 
Requires: pip install rich (recommended)
"""

from getpass import getpass
import re
import math
import secrets
import string
import time
import sys

# Try to import rich; if not present, fallback to simple output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.align import Align
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    from rich.box import ROUNDED
    from rich.layout import Layout
    from rich.rule import Rule
    USE_RICH = True
    console = Console()
except Exception:
    USE_RICH = False
    console = None

# ---------- Personal info ----------
OWNER_NAME = "Karndeep Baror"
ORG = "Cryptonic Area"
HANDLE = "@karndeepbaror"

# ---------- Helpers ----------
COMMON_BAD = [
    "password","123456","12345678","qwerty","abc123","letmein","admin",
    "welcome","iloveyou","karndeep","karndeepbaror","cryptonic","1234"
]

SEQ_PATTERNS = [
    "0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"
]

def char_sets(password):
    return {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^\w\s]", password)),
        "space": bool(re.search(r"\s", password)),
    }

def contains_sequence(pw, length=4):
    s = pw.lower()
    for seq in SEQ_PATTERNS:
        for i in range(len(seq)-length+1):
            if seq[i:i+length] in s:
                return True, seq[i:i+length]
    return False, None

def estimate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d", password): pool += 10
    if re.search(r"[^\w\s]", password): pool += 32
    if pool == 0:
        return 0.0
    return round(math.log2(pool) * len(password), 2)

def score_password(password):
    score = 0
    reasons = []
    length = len(password)
    if length == 0:
        return 0, ["No password entered"]

    # Length scoring
    if length < 8:
        score += 5
        reasons.append("Short Length (< 8).")
    elif length < 12:
        score += 18
        reasons.append("little Small (8–11).")
    elif length < 16:
        score += 32
        reasons.append("Good (12–15).")
    else:
        score += 45
        reasons.append("Excellent (>=16).")

    sets = char_sets(password)
    types = sum([sets["lower"], sets["upper"], sets["digit"], sets["symbol"]])
    score += types * 10
    if types <= 1:
        reasons.append("Only One Type of Characters - Mix Now.")
    elif types == 2:
        reasons.append("Do Types Hain, 3-4 recommended.")
    else:
        reasons.append("Character variety achhi hai.")

    low = password.lower()
    for bad in COMMON_BAD:
        if bad in low:
            score -= 25
            reasons.append(f"Common word/pattern: '{bad}'")

    seq_found, seq = contains_sequence(password, length=4)
    if seq_found:
        score -= 15
        reasons.append(f"Sequence detected: '{seq}'")

    if re.search(r"(.)\1\1", password):
        score -= 10
        reasons.append("Repeated characters detected (aaa / 111).")

    entropy = estimate_entropy(password)
    if entropy >= 70:
        score += 20
        reasons.append(f"High entropy: {entropy} bits")
    elif entropy >= 45:
        score += 8
        reasons.append(f"Moderate entropy: {entropy} bits")
    else:
        reasons.append(f"Low entropy: {entropy} bits")

    score = max(0, min(100, score))
    return score, reasons

def strength_label(score):
    if score < 20:
        return "Very Weak", "red"
    if score < 40:
        return "Weak", "dark_orange"
    if score < 60:
        return "Fair", "yellow"
    if score < 80:
        return "Good", "green"
    return "Excellent", "bright_cyan"

# Strong password generator (secure)
def generate_strong_password(length=18, use_symbols=True):
    # Use secrets for cryptographic randomness
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>/?"
    # Ensure at least one of each category
    while True:
        pw = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)
            and re.search(r"\d", pw) and (not use_symbols or re.search(r"[^\w\s]", pw))):
            return pw

# ---------- Presentation: minimal sleek banner ----------
def small_banner():
    if USE_RICH:
        t = Text()
        t.append("🔐 Password Strength Checker\n", style="bold")
        t.append(f"{OWNER_NAME} — {ORG}    ", style="dim")
        t.append(f"{HANDLE}\n", style="cyan")
        panel = Panel(Align.left(t), box=ROUNDED, padding=(0,1), border_style="magenta")
        console.print(panel)
    else:
        print("🔐 Password Strength Checker")
        print(f"{OWNER_NAME} — {ORG}    {HANDLE}")
        print("-"*40)

# ---------- Animated effects ----------
def animated_analysis(duration=1.8):
    # simple spinner/progress hybrid
    if USE_RICH:
        with Progress(SpinnerColumn(spinner_name="dots3"), TextColumn("[progress.description]{task.description}"), BarColumn(), transient=True) as prog:
            task = prog.add_task("[bold yellow]Analyzing...", total=100)
            t = 0
            while t < 100:
                step = secrets.choice([6,8,12,14])
                t = min(100, t + step)
                prog.update(task, advance=step, description=f"[bold yellow]Analyzing ({t}%)")
                time.sleep(duration/10)
    else:
        # simple dots
        print("Analyzing", end="", flush=True)
        for _ in range(6):
            print(".", end="", flush=True)
            time.sleep(duration/6)
        print()

def typing_effect(text, delay=0.02):
    if USE_RICH:
        console.print()  # gap
        for ch in text:
            console.print(ch, end="", soft_wrap=True)
            time.sleep(delay)
        console.print()
    else:
        for ch in text:
            print(ch, end="", flush=True)
            time.sleep(delay)
        print()

# ---------- Result display ----------
def display_result(password, score, reasons):
    label, color = strength_label(score)
    entropy = estimate_entropy(password)
    bar_len = 30
    filled = int((score/100)*bar_len)
    bar = "█"*filled + "─"*(bar_len-filled)

    if USE_RICH:
        table = Table(show_header=False, box=None)
        table.add_column("k")
        table.add_column("v")
        table.add_row("Score", f"[bold]{score}/100[/bold] — [{color}]{label}[/{color}]")
        table.add_row("Entropy", f"{entropy} bits")
        table.add_row("Strength", bar)
        console.print(table)
        console.print(Rule())
        # Animated suggestions lines
        for r in reasons:
            console.print("• " + r, style="white")
            time.sleep(0.12)
    else:
        print("\nRESULT")
        print(f"Score: {score}/100 -> {label}")
        print(f"Entropy: {entropy} bits")
        print("Strength: |" + bar + "|")
        print("\nSuggestions & Findings:")
        for r in reasons:
            print(" -", r)

# ---------- Hints builder ----------
def hints_for_improvement(password):
    hints = []
    sets = char_sets(password)
    if len(password) < 12:
        hints.append("Long Password: At least 12+ characters.")
    if not sets["upper"]:
        hints.append("Add sone UPPERCASE.")
    if not sets["lower"]:
        hints.append("Add Some LOWERCASE.")
    if not sets["digit"]:
        hints.append("Include Numbers (0-9).")
    if not sets["symbol"]:
        hints.append("Add Special Characters (!@#$...).")
    if re.search(r"\s", password):
        hints.append("Avoid Spaces unless intentional .")
    if any(bad in password.lower() for bad in COMMON_BAD):
        hints.append("Common words/names hatana.")
    return hints

# ---------- Main flow ----------
def main():
    # Banner
    small_banner()
    if USE_RICH:
        console.print("Enter password (typing hidden). Press Ctrl+C to quit.", style="bold yellow")
    else:
        print("Enter password (typing hidden). Press Ctrl+C to quit.")

    try:
        pw = getpass("Password: ")
    except Exception:
        pw = input("Password (visible): ")

    # Quick typing/dots to feel animated (we don't show characters)
    animated_analysis(duration=1.6)

    score, reasons = score_password(pw)
    more = hints_for_improvement(pw)
    reasons = reasons + [""] + more if more else reasons

    display_result(pw, score, reasons)

    # Quick tip panel
    if USE_RICH:
        if score < 60:
            tip = "Passphrase try karo: 4+ unrelated words + CAPS + numbers + symbols, >=12 chars."
        else:
            tip = "Strong password. Use password manager to store it safely."
        console.print(Panel(tip, title="Quick Tip", border_style="green"))
    else:
        if score < 60:
            print("\nQuick Tip: Try a passphrase - 4+ unrelated words + CAPS + nums + symbols.")
        else:
            print("\nQuick Tip: Strong password. Use a password manager.")

    # ----- Auto strong password suggestion feature -----
    if USE_RICH:
        console.print("\nIf You Want I Can Suggest a Password. (interactive)\n", style="bold cyan")
    else:
        print("\nI Can Suggest a Strong Password . (interactive)")

    while True:
        if USE_RICH:
            choice = Prompt.ask("[bold]Options[/bold]", choices=["suggest","skip","quit"], default="suggest")
        else:
            choice = input("Options - suggest / skip / quit (default suggest): ").strip().lower() or "suggest"

        if choice.startswith("s") and choice == "skip":
            if USE_RICH:
                console.print("Skipped. Bye!", style="dim")
            else:
                print("Skipped. Bye!")
            break

        if choice.startswith("q") and choice == "quit":
            if USE_RICH:
                console.print("Okay. Exit.", style="dim")
            else:
                print("Exit.")
            break

        # Suggest mode
        suggested = generate_strong_password(length=20, use_symbols=True)
        # Show with a small reveal animation
        if USE_RICH:
            console.print(Panel("Generating strong password...", border_style="magenta"))
            animated_analysis(duration=1.0)
            console.print(Panel.fit(f"[bold]{suggested}[/bold]\n\nAccept (a) / Regenerate (r) / Quit (q)", title="Suggested Password", border_style="bright_cyan"))
            sub = Prompt.ask("Choose", choices=["a","r","q"], default="a")
        else:
            print("Generating strong password...")
            animated_analysis(duration=1.0)
            print("Suggested:", suggested)
            sub = input("Choose a=accept / r=regenerate / q=quit (default a): ").strip().lower() or "a"

        if sub == "a":
            # Accepted: show final note (no file write)
            if USE_RICH:
                console.print(Panel.fit(f"[bold green]Accepted:[/bold green] {suggested}\n\n(No file saved — copy manually)", border_style="green"))
                console.print("If You Want to Re-Check This Password, We Can Analyze it Now. (y/n)", style="dim")
                again = Prompt.ask("Analyze suggested?", choices=["y","n"], default="n")
            else:
                print("Accepted:", suggested)
                again = input("Analyze suggested? (y/n, default n): ").strip().lower() or "n"

            if again == "y":
                animated_analysis(duration=1.0)
                score2, reasons2 = score_password(suggested)
                more2 = hints_for_improvement(suggested)
                reasons2 = reasons2 + [""] + more2 if more2 else reasons2
                display_result(suggested, score2, reasons2)
                if USE_RICH:
                    console.print("Done. No Files Written.", style="dim")
                else:
                    print("Done. No files written.")
            # finalize and exit loop
            break
        elif sub == "r":
            # regenerate loop again
            if USE_RICH:
                console.print("Regenerating...", style="dim")
            continue
        elif sub == "q":
            if USE_RICH:
                console.print("Quit suggestion mode.", style="dim")
            break
        else:
            # fallback
            break

    # End signature
    end_msg = f"Checked by {OWNER_NAME} ({HANDLE}) — Results Shown Only in Terminal. No Files Were Written."
    if USE_RICH:
        console.print("\n" + end_msg, style="bold dim")
    else:
        print("\n" + end_msg)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if USE_RICH:
            console.print("\nInterrupted. Bye!", style="red")
        else:
            print("\nInterrupted. Bye!")
        sys.exit(0)
