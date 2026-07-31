"""
CyberSec Toolkit — Main CLI
A comprehensive cybersecurity utility for modern-day security tasks.
"""

import sys
import os

# Ensure the package root is importable when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.columns import Columns
from rich.rule import Rule

from cybersec_toolkit import __version__
from cybersec_toolkit.modules import (
    password_analyzer,
    password_generator,
    hash_tools,
    file_integrity,
    port_scanner,
    cipher_tools,
    network_tools,
)

console = Console()

# ─── Colour palette ───────────────────────────────────────────────────────────
STRENGTH_COLORS = {
    "Very Weak": "red",
    "Weak": "orange3",
    "Moderate": "yellow",
    "Strong": "green",
    "Very Strong": "bright_green",
}

RISK_COLORS = {
    "Critical": "bright_red",
    "High": "red",
    "Medium": "yellow",
    "Low": "green",
    "": "dim white",
}


# ─── Banner ───────────────────────────────────────────────────────────────────

def show_banner() -> None:
    banner = Text(justify="center")
    banner.append("\n")
    banner.append("  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗ \n", style="bright_cyan")
    banner.append(" ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝ \n", style="bright_cyan")
    banner.append(" ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║      \n", style="cyan")
    banner.append(" ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║      \n", style="cyan")
    banner.append(" ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗ \n", style="blue")
    banner.append("  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ \n", style="blue")
    banner.append(f"\n  CyberSec Toolkit v{__version__}  |  Modern Cybersecurity Utilities\n", style="bold white")
    console.print(Panel(banner, border_style="bright_cyan", padding=(0, 2)))


# ─── Main Menu ────────────────────────────────────────────────────────────────

MENU_ITEMS = [
    ("1", "Password Analyzer",     "Check the strength of a password"),
    ("2", "Password Generator",    "Generate secure passwords & passphrases"),
    ("3", "Hash Tools",            "Hash text or files (SHA-256, MD5, …)"),
    ("4", "File Integrity",        "Create/verify file integrity manifests"),
    ("5", "Port Scanner",          "Scan TCP ports on a host"),
    ("6", "Cipher Tools",          "Encrypt/decrypt with classical ciphers"),
    ("7", "Network Tools",         "DNS lookup, SSL cert info, IP geo"),
    ("0", "Exit",                  "Quit the toolkit"),
]


def show_main_menu() -> None:
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
                  border_style="cyan", expand=False)
    table.add_column("Option", style="bold yellow", width=8, justify="center")
    table.add_column("Module", style="bold white", width=24)
    table.add_column("Description", style="dim white")

    for key, name, desc in MENU_ITEMS:
        style = "on grey15" if int(key) % 2 == 0 else ""
        table.add_row(f"[{key}]", name, desc, style=style)

    console.print()
    console.print(table)
    console.print()


# ─── Password Analyzer ────────────────────────────────────────────────────────

def menu_password_analyzer() -> None:
    console.print(Rule("[bold cyan]Password Strength Analyzer[/bold cyan]"))
    console.print("[dim]Your password is never transmitted or stored.[/dim]\n")

    password = Prompt.ask("[bold]Enter password to analyze[/bold]", password=True)
    with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing…"), transient=True, console=console):
        import time; time.sleep(0.3)
        result = password_analyzer.analyze_password(password)

    # Strength bar
    color = STRENGTH_COLORS.get(result.strength, "white")
    bar_filled = int(result.percentage / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    console.print(f"\n  Strength: [{color}]{result.strength}[/{color}]  [{color}]{bar}[/{color}]  {result.percentage}%")
    console.print(f"  Entropy:  [cyan]{result.entropy_bits} bits[/cyan]\n")

    # Criteria table
    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold", border_style="dim")
    t.add_column("Criterion", style="bold white")
    t.add_column("Detail", style="cyan")
    t.add_column("Score", justify="right")

    c = result.criteria
    t.add_row("Length",
              f"{c['length']['value']} characters",
              f"[{'green' if c['length']['score'] >= 20 else 'yellow'}]{c['length']['score']}/{c['length']['max']}[/]")

    v = c["variety"]
    checks = []
    for label, key in [("a-z", "lowercase"), ("A-Z", "uppercase"), ("0-9", "digits"), ("!@#", "special")]:
        checks.append(f"[green]✓ {label}[/green]" if v[key] else f"[red]✗ {label}[/red]")
    t.add_row("Character types", "  ".join(checks),
              f"[{'green' if v['score'] >= 20 else 'yellow'}]{v['score']}/{v['max']}[/]")

    t.add_row("Entropy",
              f"{c['entropy']['bits']} bits",
              f"[{'green' if c['entropy']['score'] >= 15 else 'yellow'}]{c['entropy']['score']}/{c['entropy']['max']}[/]")

    t.add_row("Pattern-free",
              "[green]✓ No patterns detected[/green]" if c['patterns']['score'] == 10 else "[red]✗ Patterns found[/red]",
              f"{c['patterns']['score']}/{c['patterns']['max']}")

    t.add_row("Not common",
              "[red]✗ Common password![/red]" if c['common']['is_common'] else "[green]✓ Not a common password[/green]",
              f"{c['common']['score']}/{c['common']['max']}")

    console.print(t)

    if result.issues:
        console.print("\n[bold red]Issues found:[/bold red]")
        for issue in result.issues:
            console.print(f"  [red]•[/red] {issue}")

    if result.suggestions:
        console.print("\n[bold yellow]Suggestions:[/bold yellow]")
        for sug in result.suggestions:
            console.print(f"  [yellow]→[/yellow] {sug}")


# ─── Password Generator ───────────────────────────────────────────────────────

def menu_password_generator() -> None:
    console.print(Rule("[bold cyan]Secure Password Generator[/bold cyan]"))

    options = ["1 - Random password", "2 - Passphrase (memorable words)", "3 - Numeric PIN", "4 - Estimate crack time for a password"]
    for o in options:
        console.print(f"  [yellow]{o}[/yellow]")

    choice = Prompt.ask("\nChoice", choices=["1", "2", "3", "4"], default="1")

    if choice == "1":
        length = IntPrompt.ask("Password length", default=20)
        use_upper = Confirm.ask("Include uppercase letters?", default=True)
        use_lower = Confirm.ask("Include lowercase letters?", default=True)
        use_digits = Confirm.ask("Include digits?", default=True)
        use_special = Confirm.ask("Include special characters?", default=True)
        exclude_ambiguous = Confirm.ask("Exclude ambiguous characters (0, O, 1, l, I)?", default=False)

        cfg = password_generator.GeneratorConfig(
            length=length,
            use_uppercase=use_upper,
            use_lowercase=use_lower,
            use_digits=use_digits,
            use_special=use_special,
            exclude_ambiguous=exclude_ambiguous,
        )
        try:
            pwd = password_generator.generate_password(cfg)
            console.print(f"\n[bold]Generated password:[/bold] [bright_green]{pwd}[/bright_green]")
            console.print("[dim](Copy it now — it will not be stored)[/dim]")

            # Show its strength
            result = password_analyzer.analyze_password(pwd)
            color = STRENGTH_COLORS.get(result.strength, "white")
            console.print(f"Strength: [{color}]{result.strength}[/{color}] ({result.percentage}%)")
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")

    elif choice == "2":
        num_words = IntPrompt.ask("Number of words", default=4)
        sep = Prompt.ask("Separator", default="-")
        phrase = password_generator.generate_passphrase(num_words=num_words, separator=sep)
        console.print(f"\n[bold]Passphrase:[/bold] [bright_green]{phrase}[/bright_green]")

    elif choice == "3":
        length = IntPrompt.ask("PIN length", default=6)
        pin = password_generator.generate_pin(length)
        console.print(f"\n[bold]PIN:[/bold] [bright_green]{pin}[/bright_green]")

    elif choice == "4":
        pwd = Prompt.ask("Enter password to estimate", password=True)
        info = password_generator.estimate_crack_time(pwd)

        t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
        t.add_column("Attack Scenario", style="white")
        t.add_column("Estimated Time", style="bright_cyan")
        for scenario, estimate in info.get("estimates", {}).items():
            t.add_row(scenario, estimate)

        console.print(f"\nCharacter space: ~{info.get('combinations', 0):,} combinations")
        console.print(f"Entropy: {info.get('entropy_bits', 0)} bits\n")
        console.print(t)


# ─── Hash Tools ───────────────────────────────────────────────────────────────

def menu_hash_tools() -> None:
    console.print(Rule("[bold cyan]Hash Tools[/bold cyan]"))

    options = ["1 - Hash text", "2 - Hash all algorithms", "3 - Verify hash", "4 - Hash file", "5 - Generate HMAC", "6 - Verify HMAC"]
    for o in options:
        console.print(f"  [yellow]{o}[/yellow]")

    choice = Prompt.ask("\nChoice", choices=["1", "2", "3", "4", "5", "6"], default="1")

    if choice == "1":
        text = Prompt.ask("Text to hash")
        algo = Prompt.ask("Algorithm", default="sha256",
                          choices=list(hash_tools.SUPPORTED_ALGORITHMS.keys()))
        result = hash_tools.hash_text(text, algo)
        _print_hash_result(result)

    elif choice == "2":
        text = Prompt.ask("Text to hash")
        results = hash_tools.hash_all(text)
        t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
        t.add_column("Algorithm", style="cyan", width=14)
        t.add_column("Digest", style="white")
        t.add_column("Security", width=14)
        for r in results:
            status = r["security_status"]
            color = {"Broken": "red", "Deprecated": "orange3", "Acceptable": "yellow",
                     "Recommended": "green", "Strong": "bright_green"}.get(status, "white")
            t.add_row(r["algorithm"], r["digest"], f"[{color}]{status}[/{color}]")
        console.print(t)

    elif choice == "3":
        text = Prompt.ask("Text to verify")
        expected = Prompt.ask("Expected hash")
        algo = Prompt.ask("Algorithm", default="sha256")
        match = hash_tools.verify_hash(text, expected, algo)
        if match:
            console.print("[bold bright_green]✓ Hash matches![/bold bright_green]")
        else:
            console.print("[bold red]✗ Hash does NOT match.[/bold red]")

    elif choice == "4":
        path = Prompt.ask("File path")
        algo = Prompt.ask("Algorithm", default="sha256")
        try:
            result = hash_tools.hash_file(path, algo)
            _print_hash_result(result)
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]Error: {e}[/red]")

    elif choice == "5":
        msg = Prompt.ask("Message")
        key = Prompt.ask("Secret key", password=True)
        algo = Prompt.ask("Algorithm", default="sha256")
        result = hash_tools.generate_hmac(msg, key, algo)
        console.print(f"\n[cyan]{result['algorithm']}:[/cyan] [white]{result['digest']}[/white]")
        console.print(f"[dim]{result['note']}[/dim]")

    elif choice == "6":
        msg = Prompt.ask("Message")
        key = Prompt.ask("Secret key", password=True)
        expected = Prompt.ask("Expected HMAC")
        algo = Prompt.ask("Algorithm", default="sha256")
        match = hash_tools.verify_hmac(msg, key, expected, algo)
        if match:
            console.print("[bold bright_green]✓ HMAC is valid![/bold bright_green]")
        else:
            console.print("[bold red]✗ HMAC is INVALID — message may have been tampered with.[/bold red]")


def _print_hash_result(result: dict) -> None:
    console.print(f"\n[bold cyan]{result.get('algorithm', '')}:[/bold cyan]")
    console.print(f"  Digest : [white]{result['digest']}[/white]")
    if "file_size_bytes" in result:
        console.print(f"  File   : {result['file']} ({result['file_size_bytes']:,} bytes)")
    status = result.get("security_status", "")
    color = {"Broken": "red", "Deprecated": "orange3", "Acceptable": "yellow",
             "Recommended": "green", "Strong": "bright_green"}.get(status, "white")
    if status:
        console.print(f"  Status : [{color}]{status}[/{color}] — {result.get('security_note', '')}")


# ─── File Integrity ───────────────────────────────────────────────────────────

def menu_file_integrity() -> None:
    console.print(Rule("[bold cyan]File Integrity Checker[/bold cyan]"))

    options = ["1 - Create integrity manifest", "2 - Verify manifest", "3 - Check single file hash"]
    for o in options:
        console.print(f"  [yellow]{o}[/yellow]")

    choice = Prompt.ask("\nChoice", choices=["1", "2", "3"], default="1")

    if choice == "1":
        paths_str = Prompt.ask("Files/directories to include (comma-separated)")
        paths = [p.strip() for p in paths_str.split(",") if p.strip()]
        output = Prompt.ask("Output manifest file", default="integrity_manifest.json")
        algo = Prompt.ask("Hash algorithm", default="sha256")

        with Progress(SpinnerColumn(), TextColumn("[cyan]Hashing files…"), transient=True, console=console):
            result = file_integrity.create_manifest(paths, output, algo)

        console.print(f"\n[green]✓ Manifest created:[/green] {result['manifest_file']}")
        console.print(f"  Files processed : {result['files_processed']}")
        console.print(f"  Algorithm       : {result['algorithm']}")
        if result["errors"]:
            console.print(f"[red]Errors:[/red]")
            for e in result["errors"]:
                console.print(f"  [red]•[/red] {e}")

    elif choice == "2":
        manifest = Prompt.ask("Manifest file path", default="integrity_manifest.json")
        try:
            with Progress(SpinnerColumn(), TextColumn("[cyan]Verifying…"), transient=True, console=console):
                result = file_integrity.verify_manifest(manifest)

            status_color = "bright_green" if result["overall_status"] == "PASS" else "bright_red"
            console.print(f"\nOverall: [{status_color}]{result['overall_status']}[/{status_color}]")
            console.print(f"  Checked : {result['total_files']} files")
            console.print(f"  Passed  : [green]{len(result['passed'])}[/green]")
            console.print(f"  Failed  : [red]{len(result['failed'])}[/red]")
            console.print(f"  Missing : [yellow]{len(result['missing'])}[/yellow]")

            if result["failed"]:
                console.print("\n[bold red]TAMPERED / CHANGED FILES:[/bold red]")
                for f in result["failed"]:
                    console.print(f"  [red]✗[/red] {f['file']}")
                    console.print(f"      [dim]Reason: {f['reason']}[/dim]")

            if result["missing"]:
                console.print("\n[bold yellow]MISSING FILES:[/bold yellow]")
                for m in result["missing"]:
                    console.print(f"  [yellow]![/yellow] {m['file']}")

        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")

    elif choice == "3":
        path = Prompt.ask("File path")
        algo = Prompt.ask("Algorithm", default="sha256")
        try:
            result = file_integrity.check_single_file(path, algo)
            _print_hash_result(result)
            console.print(f"  Modified: {result.get('modified_at', '')}")
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]Error: {e}[/red]")


# ─── Port Scanner ─────────────────────────────────────────────────────────────

def menu_port_scanner() -> None:
    console.print(Rule("[bold cyan]Port Scanner[/bold cyan]"))
    console.print("[dim]Only scan hosts you own or have explicit permission to scan.[/dim]\n")

    target = Prompt.ask("Target hostname or IP")

    scan_type = Prompt.ask(
        "Scan type",
        choices=["common", "range", "custom"],
        default="common",
    )

    ports = None
    port_range = None

    if scan_type == "range":
        start = IntPrompt.ask("Start port", default=1)
        end = IntPrompt.ask("End port", default=1024)
        port_range = (start, end)
    elif scan_type == "custom":
        ports_str = Prompt.ask("Ports (comma-separated, e.g. 22,80,443)")
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]

    timeout = float(Prompt.ask("Timeout per port (seconds)", default="1.0"))
    grab_banners = Confirm.ask("Attempt banner grabbing on open ports?", default=False)

    with Progress(SpinnerColumn(), TextColumn(f"[cyan]Scanning {target}…"), transient=True, console=console):
        result = port_scanner.scan(
            target=target,
            ports=ports,
            port_range=port_range,
            timeout=timeout,
            grab_banners=grab_banners,
        )

    if result.error:
        console.print(f"[red]Error: {result.error}[/red]")
        return

    console.print(f"\n[bold]Scan Results for[/bold] [cyan]{result.target}[/cyan] ([dim]{result.target_ip}[/dim])")
    console.print(f"  Ports scanned : {result.ports_scanned}")
    console.print(f"  Open ports    : [green]{len(result.open_ports)}[/green]")
    console.print(f"  Duration      : {result.duration_seconds}s\n")

    if not result.open_ports:
        console.print("[dim]No open ports found.[/dim]")
        return

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan", border_style="dim")
    t.add_column("Port", style="yellow", width=8)
    t.add_column("Service", style="white", width=22)
    t.add_column("Response", justify="right", width=12)
    t.add_column("Risk", width=10)
    t.add_column("Banner / Note", style="dim")

    for pr in result.open_ports:
        risk_color = RISK_COLORS.get(pr.risk_level, "dim white")
        risk_display = f"[{risk_color}]{pr.risk_level}[/{risk_color}]" if pr.risk_level else "[dim]—[/dim]"
        banner_or_note = pr.banner or (pr.risk_note if pr.risk_level else "")
        t.add_row(str(pr.port), pr.service, f"{pr.response_ms}ms", risk_display, banner_or_note)

    console.print(t)


# ─── Cipher Tools ─────────────────────────────────────────────────────────────

def menu_cipher_tools() -> None:
    console.print(Rule("[bold cyan]Cipher & Encoding Tools[/bold cyan]"))

    options = [
        "1 - Caesar cipher",
        "2 - Vigenere cipher",
        "3 - XOR encryption",
        "4 - ROT13",
        "5 - Base64 encode/decode",
        "6 - URL encode/decode",
        "7 - Hex encode/decode",
        "8 - One-Time Pad (OTP)",
    ]
    for o in options:
        console.print(f"  [yellow]{o}[/yellow]")

    choice = Prompt.ask("\nChoice", choices=[str(i) for i in range(1, 9)], default="1")

    if choice == "1":
        action = Prompt.ask("Action", choices=["encrypt", "decrypt", "brute-force"], default="encrypt")
        text = Prompt.ask("Text")
        if action == "brute-force":
            results = cipher_tools.caesar_brute_force(text)
            t = Table(box=box.SIMPLE, show_header=True)
            t.add_column("Shift", style="yellow", width=8)
            t.add_column("Plaintext", style="white")
            for r in results:
                t.add_row(str(r["shift"]), r["plaintext"])
            console.print(t)
        else:
            shift = IntPrompt.ask("Shift value (1-25)", default=13)
            fn = cipher_tools.caesar_encrypt if action == "encrypt" else cipher_tools.caesar_decrypt
            console.print(f"\n[cyan]Result:[/cyan] {fn(text, shift)}")

    elif choice == "2":
        action = Prompt.ask("Action", choices=["encrypt", "decrypt"], default="encrypt")
        text = Prompt.ask("Text")
        key = Prompt.ask("Key (letters only)")
        try:
            fn = cipher_tools.vigenere_encrypt if action == "encrypt" else cipher_tools.vigenere_decrypt
            console.print(f"\n[cyan]Result:[/cyan] {fn(text, key)}")
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")

    elif choice == "3":
        action = Prompt.ask("Action", choices=["encrypt", "decrypt"], default="encrypt")
        key = Prompt.ask("Key")
        if action == "encrypt":
            text = Prompt.ask("Text to encrypt")
            result = cipher_tools.xor_encrypt(text, key)
            console.print(f"\n[cyan]Hex:[/cyan]    {result['ciphertext_hex']}")
            console.print(f"[cyan]Base64:[/cyan] {result['ciphertext_b64']}")
            console.print(f"[dim]{result['note']}[/dim]")
        else:
            hex_in = Prompt.ask("Ciphertext (hex)")
            try:
                console.print(f"\n[cyan]Decrypted:[/cyan] {cipher_tools.xor_decrypt(hex_in, key)}")
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")

    elif choice == "4":
        text = Prompt.ask("Text")
        console.print(f"\n[cyan]ROT13:[/cyan] {cipher_tools.rot13(text)}")

    elif choice == "5":
        action = Prompt.ask("Action", choices=["encode", "decode"], default="encode")
        text = Prompt.ask("Text")
        if action == "encode":
            result = cipher_tools.base64_encode(text)
            console.print(f"\n[cyan]Standard:[/cyan] {result['encoded']}")
            console.print(f"[cyan]URL-safe:[/cyan] {result['url_safe']}")
            console.print(f"[dim]{result['note']}[/dim]")
        else:
            try:
                console.print(f"\n[cyan]Decoded:[/cyan] {cipher_tools.base64_decode(text)}")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    elif choice == "6":
        action = Prompt.ask("Action", choices=["encode", "decode"], default="encode")
        text = Prompt.ask("Text")
        if action == "encode":
            result = cipher_tools.url_encode(text)
            console.print(f"\n[cyan]Encoded:[/cyan]      {result['encoded']}")
            console.print(f"[cyan]Encoded (+):[/cyan]  {result['encoded_plus']}")
        else:
            console.print(f"\n[cyan]Decoded:[/cyan] {cipher_tools.url_decode(text)}")

    elif choice == "7":
        action = Prompt.ask("Action", choices=["encode", "decode"], default="encode")
        text = Prompt.ask("Text")
        if action == "encode":
            console.print(f"\n[cyan]Hex:[/cyan] {cipher_tools.to_hex(text)}")
        else:
            try:
                console.print(f"\n[cyan]Decoded:[/cyan] {cipher_tools.from_hex(text)}")
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")

    elif choice == "8":
        action = Prompt.ask("Action", choices=["generate-key", "encrypt", "decrypt"], default="generate-key")
        if action == "generate-key":
            length = IntPrompt.ask("Message length (bytes)", default=32)
            key = cipher_tools.otp_generate_key(length)
            console.print(f"\n[cyan]OTP Key (hex):[/cyan] [bright_green]{key}[/bright_green]")
            console.print("[dim]Store this key securely and use it only ONCE.[/dim]")
        elif action == "encrypt":
            text = Prompt.ask("Text to encrypt")
            key = Prompt.ask("OTP key (hex)")
            try:
                result = cipher_tools.otp_encrypt(text, key)
                console.print(f"\n[cyan]Ciphertext (hex):[/cyan] {result['ciphertext_hex']}")
                console.print(f"[dim]{result['note']}[/dim]")
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
        else:
            ciphertext = Prompt.ask("Ciphertext (hex)")
            key = Prompt.ask("OTP key (hex)")
            try:
                console.print(f"\n[cyan]Decrypted:[/cyan] {cipher_tools.otp_decrypt(ciphertext, key)}")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")


# ─── Network Tools ────────────────────────────────────────────────────────────

def menu_network_tools() -> None:
    console.print(Rule("[bold cyan]Network Tools[/bold cyan]"))

    options = [
        "1 - DNS lookup",
        "2 - SSL certificate info",
        "3 - IP geolocation",
        "4 - Host profile (DNS + IP + SSL)",
        "5 - Check port reachability",
    ]
    for o in options:
        console.print(f"  [yellow]{o}[/yellow]")

    choice = Prompt.ask("\nChoice", choices=["1", "2", "3", "4", "5"], default="1")

    if choice == "1":
        host = Prompt.ask("Hostname or IP")
        with Progress(SpinnerColumn(), TextColumn("[cyan]Looking up…"), transient=True, console=console):
            result = network_tools.dns_lookup(host)

        if result["error"]:
            console.print(f"[red]Error: {result['error']}[/red]")
            return
        console.print(f"\n[bold]Forward records for [cyan]{host}[/cyan]:[/bold]")
        for ip in result["forward_records"]:
            console.print(f"  → {ip}")
        console.print("\n[bold]Reverse records:[/bold]")
        for r in result["reverse_records"]:
            console.print(f"  {r['ip']} → {r['hostname']}")

    elif choice == "2":
        host = Prompt.ask("Hostname")
        port = IntPrompt.ask("Port", default=443)
        with Progress(SpinnerColumn(), TextColumn("[cyan]Checking certificate…"), transient=True, console=console):
            result = network_tools.get_ssl_certificate_info(host, port)

        if result["error"]:
            console.print(f"[red]Error: {result['error']}[/red]")
            for w in result.get("warnings", []):
                console.print(f"[yellow]{w}[/yellow]")
            return

        cert = result["certificate"]
        expiry_color = "red" if cert["is_expired"] else ("yellow" if cert["days_until_expiry"] < 30 else "green")

        console.print(f"\n[bold]SSL Certificate for [cyan]{host}:{port}[/cyan][/bold]")
        t = Table(box=box.SIMPLE_HEAD, show_header=False, border_style="dim")
        t.add_column("Field", style="dim", width=20)
        t.add_column("Value")
        t.add_row("Common Name", cert.get("common_name", ""))
        t.add_row("Issuer", cert.get("issuer", {}).get("organizationName", str(cert.get("issuer", ""))))
        t.add_row("Valid From", cert["not_before"])
        t.add_row("Expires", f"[{expiry_color}]{cert['not_after']} ({cert['days_until_expiry']} days)[/{expiry_color}]")
        t.add_row("TLS Version", cert["tls_version"])
        t.add_row("Cipher", cert["cipher_suite"])
        console.print(t)

        for w in result.get("warnings", []):
            console.print(f"[yellow]⚠ {w}[/yellow]")

    elif choice == "3":
        ip = Prompt.ask("IP address (leave blank for your public IP)", default="")
        with Progress(SpinnerColumn(), TextColumn("[cyan]Looking up…"), transient=True, console=console):
            result = network_tools.get_ip_info(ip or None)

        if "error" in result:
            console.print(f"[red]Error: {result['error']}[/red]")
            return

        t = Table(box=box.SIMPLE_HEAD, show_header=False, border_style="dim")
        t.add_column("Field", style="dim", width=14)
        t.add_column("Value")
        for key in ("query", "country", "regionName", "city", "zip", "isp", "org", "as", "timezone"):
            if key in result:
                t.add_row(key.replace("regionName", "Region").replace("query", "IP"), str(result[key]))
        console.print(t)

    elif choice == "4":
        host = Prompt.ask("Hostname")
        with Progress(SpinnerColumn(), TextColumn("[cyan]Profiling host…"), transient=True, console=console):
            result = network_tools.whois_like_info(host)

        console.print(f"\n[bold]Host Profile: [cyan]{host}[/cyan][/bold]")

        dns = result.get("dns", {})
        if not dns.get("error"):
            console.print("\n[bold]DNS[/bold]")
            for ip in dns.get("forward_records", []):
                console.print(f"  A record → {ip}")

        ip_info = result.get("ip_info", {})
        if ip_info and "error" not in ip_info:
            console.print("\n[bold]IP Geolocation[/bold]")
            console.print(f"  ISP     : {ip_info.get('isp', '')}")
            console.print(f"  Location: {ip_info.get('city', '')}, {ip_info.get('regionName', '')}, {ip_info.get('country', '')}")

        ssl_info = result.get("ssl", {})
        if ssl_info:
            cert = ssl_info.get("certificate", {})
            expiry_color = "red" if cert.get("is_expired") else "green"
            console.print("\n[bold]SSL Certificate[/bold]")
            console.print(f"  Issuer  : {cert.get('issuer', {}).get('organizationName', 'N/A')}")
            console.print(f"  Expires : [{expiry_color}]{cert.get('days_until_expiry', '?')} days[/{expiry_color}]")
            console.print(f"  TLS     : {cert.get('tls_version', 'N/A')}")

    elif choice == "5":
        host = Prompt.ask("Hostname or IP")
        port = IntPrompt.ask("Port", default=443)
        result = network_tools.check_port_publicly_reachable(host, port)
        if result["reachable"]:
            console.print(f"\n[green]✓ {host}:{port} is reachable[/green] ({result['response_ms']}ms)")
        else:
            console.print(f"\n[red]✗ {host}:{port} is NOT reachable[/red] — {result.get('error', '')}")


# ─── Main Loop ────────────────────────────────────────────────────────────────

HANDLERS = {
    "1": menu_password_analyzer,
    "2": menu_password_generator,
    "3": menu_hash_tools,
    "4": menu_file_integrity,
    "5": menu_port_scanner,
    "6": menu_cipher_tools,
    "7": menu_network_tools,
}


def main() -> None:
    show_banner()

    while True:
        show_main_menu()
        choice = Prompt.ask("[bold yellow]Select an option[/bold yellow]", default="0")

        if choice == "0":
            console.print("\n[cyan]Stay secure. Goodbye![/cyan]\n")
            break

        handler = HANDLERS.get(choice)
        if handler:
            console.print()
            try:
                handler()
            except KeyboardInterrupt:
                console.print("\n[dim]← Back to main menu[/dim]")
        else:
            console.print("[red]Invalid option.[/red]")

        console.print()
        Prompt.ask("[dim]Press Enter to return to the main menu[/dim]", default="")


if __name__ == "__main__":
    main()
