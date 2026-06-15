#!/usr/bin/env python3
"""
SSL Trust Chain Checker — mini SSLLabs alternative.
Connects to a host, fetches the certificate chain, and shows:
  - each cert in the chain (server / intermediate / root)
  - whether it is present in the system/certifi trust store
  - whether it was sent by the server or comes from the local store
  - what is missing to make the chain complete
"""

import sys
import ssl
import socket
import subprocess
import datetime
import warnings
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID
from rich.console import Console
from rich.panel import Panel

console = Console()


# ---------------------------------------------------------------------------
# Trust store helpers
# ---------------------------------------------------------------------------

def _load_trusted_certs() -> dict[bytes, x509.Certificate]:
    """Load certifi CA bundle, keyed by subject DER bytes."""
    trusted: dict[bytes, x509.Certificate] = {}
    pem_data = Path(certifi.where()).read_bytes()
    # Split on -----BEGIN CERTIFICATE-----
    pem_blocks: list[bytes] = []
    current: list[bytes] = []
    for line in pem_data.splitlines(keepends=True):
        if line.strip() == b"-----BEGIN CERTIFICATE-----" and current:
            pem_blocks.append(b"".join(current))
            current = []
        current.append(line)
    if current:
        pem_blocks.append(b"".join(current))

    for pem in pem_blocks:
        if b"BEGIN CERTIFICATE" not in pem:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                cert = x509.load_pem_x509_certificate(pem)
            trusted[cert.subject.public_bytes()] = cert
        except Exception:
            pass
    return trusted


TRUSTED: dict[bytes, x509.Certificate] = _load_trusted_certs()


def is_trusted(cert: x509.Certificate) -> bool:
    return cert.subject.public_bytes() in TRUSTED


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------

def cert_cn(cert: x509.Certificate) -> str:
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        return cert.subject.rfc4514_string()


def cert_issuer_cn(cert: x509.Certificate) -> str:
    try:
        return cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        return cert.issuer.rfc4514_string()


def cert_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [str(n.value) for n in ext.value]
    except x509.ExtensionNotFound:
        return []


def cert_fingerprint(cert: x509.Certificate) -> str:
    fp = cert.fingerprint(hashes.SHA256())
    hex_fp = fp.hex().upper()
    return ":".join(hex_fp[i:i+2] for i in range(0, len(hex_fp), 2))


def key_info(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC {pub.curve.name} {pub.key_size}"
    return type(pub).__name__


def is_self_signed(cert: x509.Certificate) -> bool:
    return cert.subject.public_bytes() == cert.issuer.public_bytes()


def is_expired(cert: x509.Certificate) -> bool:
    now = datetime.datetime.now(datetime.timezone.utc)
    return cert.not_valid_after_utc < now


def days_remaining(cert: x509.Certificate) -> int:
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = cert.not_valid_after_utc - now
    return delta.days


def cert_serial(cert: x509.Certificate) -> str:
    n = cert.serial_number
    h = f"{n:x}"
    if len(h) % 2:
        h = "0" + h
    return ":".join(h[i:i+2] for i in range(0, len(h), 2)).upper()


def cert_ski(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        return ext.value.digest.hex(":").upper()
    except x509.ExtensionNotFound:
        return None


def cert_aki(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        if ext.value.key_identifier:
            return ext.value.key_identifier.hex(":").upper()
    except x509.ExtensionNotFound:
        pass
    return None


def cert_aia_issuers(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        return [
            str(ad.access_location.value)
            for ad in ext.value
            if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        ]
    except x509.ExtensionNotFound:
        return []


# ---------------------------------------------------------------------------
# TLS connection — fetch chain
# ---------------------------------------------------------------------------

def _parse_pem_blocks(text: str) -> list[bytes]:
    """Extract all PEM certificate blocks from openssl s_client output."""
    blocks: list[bytes] = []
    current: list[str] = []
    in_cert = False
    for line in text.splitlines():
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            current = [line]
        elif "-----END CERTIFICATE-----" in line and in_cert:
            current.append(line)
            blocks.append(("\n".join(current)).encode())
            in_cert = False
            current = []
        elif in_cert:
            current.append(line)
    return blocks


def _fetch_server_chain(host: str, port: int) -> list[bytes]:
    """Use openssl s_client -showcerts to get all certs the server sends."""
    result = subprocess.run(
        [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-showcerts",
        ],
        input=b"Q\n",
        capture_output=True,
        timeout=15,
    )
    output = result.stdout.decode("utf-8", errors="replace")
    return _parse_pem_blocks(output)


def _verify_tls(host: str, port: int) -> bool:
    """Return True if the certificate chain verifies against certifi trust store."""
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLCertVerificationError:
        return False


def fetch_chain(host: str, port: int = 443) -> tuple[list[x509.Certificate], bool, set[bytes], list[x509.Certificate]]:
    """
    Returns (chain, verified_ok, server_subjects).
    chain[0] is the leaf certificate.
    server_subjects contains subject DER bytes of certs actually sent by the server.
    """
    server_pem_blocks = _fetch_server_chain(host, port)
    if not server_pem_blocks:
        raise RuntimeError("openssl s_client returned no certificates")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        server_certs = [x509.load_pem_x509_certificate(p) for p in server_pem_blocks]
    server_subjects: set[bytes] = {c.subject.public_bytes() for c in server_certs}

    # Index all server certs by subject for fast lookup
    by_subject: dict[bytes, x509.Certificate] = {
        c.subject.public_bytes(): c for c in server_certs
    }

    # Walk the chain: leaf → intermediates → root
    leaf = server_certs[0]
    ordered: list[x509.Certificate] = [leaf]
    visited: set[bytes] = {leaf.subject.public_bytes()}
    current = leaf
    for _ in range(20):
        if is_self_signed(current) or is_trusted(current):
            break
        issuer_key = current.issuer.public_bytes()
        if issuer_key in visited:
            break
        if issuer_key in by_subject:
            nxt = by_subject[issuer_key]
            ordered.append(nxt)
            visited.add(issuer_key)
            current = nxt
        elif issuer_key in TRUSTED:
            ordered.append(TRUSTED[issuer_key])
            break
        else:
            break

    # Certs the server sent that are NOT on the valid path
    extra = [c for c in server_certs if c.subject.public_bytes() not in visited]

    verified_ok = _verify_tls(host, port)
    return ordered, verified_ok, server_subjects, extra


# ---------------------------------------------------------------------------
# Chain analysis
# ---------------------------------------------------------------------------

def analyse_chain(
    certs: list[x509.Certificate],
    host: str,
    server_subjects: set[bytes],
    extra: list[x509.Certificate],
) -> dict:
    """
    Returns structured analysis of the chain.
    certs: ordered leaf → root (valid path).
    server_subjects: subject DER bytes of certs actually sent by the server.
    extra: certs sent by server that are NOT part of the valid path.
    """

    result = {
        "host": host,
        "certs": [],
        "extra_certs": [],
        "chain_complete": False,
        "missing_cert": None,
    }

    for i, cert in enumerate(certs):
        role = "leaf" if i == 0 else ("root" if (is_self_signed(cert) or is_trusted(cert)) else "intermediate")
        from_server = cert.subject.public_bytes() in server_subjects
        trusted_locally = is_trusted(cert)

        entry = {
            "index": i,
            "role": role,
            "cn": cert_cn(cert),
            "issuer_cn": cert_issuer_cn(cert),
            "sans": cert_sans(cert) if role == "leaf" else [],
            "key": key_info(cert),
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "days_remaining": days_remaining(cert),
            "expired": is_expired(cert),
            "self_signed": is_self_signed(cert),
            "from_server": from_server,
            "trusted_locally": trusted_locally,
            "fingerprint": cert_fingerprint(cert),
            "serial": cert_serial(cert),
            "ski": cert_ski(cert),
            "aki": cert_aki(cert),
            "aia_issuers": cert_aia_issuers(cert),
        }
        result["certs"].append(entry)

    # Is the chain complete?
    # Complete when the last cert anchors to trust:
    #   - self-signed root, OR
    #   - last cert is itself in the trust store (cross-signed root), OR
    #   - issuer of last cert is in the trust store
    for cert in extra:
        result["extra_certs"].append({
            "cn": cert_cn(cert),
            "issuer_cn": cert_issuer_cn(cert),
            "key": key_info(cert),
            "expired": is_expired(cert),
            "days_remaining": days_remaining(cert),
        })

    result["missing_aki"] = None
    result["missing_aia_issuers"] = []

    if certs:
        last = certs[-1]
        if is_self_signed(last):
            result["chain_complete"] = True
        elif is_trusted(last):
            result["chain_complete"] = True
        else:
            issuer_subject = last.issuer.public_bytes()
            if issuer_subject in TRUSTED:
                result["chain_complete"] = True
                result["missing_cert"] = cert_cn(TRUSTED[issuer_subject]) + " (in local trust store, not sent by server)"
            else:
                result["chain_complete"] = False
                result["missing_cert"] = f"Issuer of '{cert_cn(last)}': {cert_issuer_cn(last)}"
                result["missing_aki"] = cert_aki(last)
                result["missing_aia_issuers"] = cert_aia_issuers(last)

    return result


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

ROLE_COLOR = {
    "leaf": "green",
    "intermediate": "yellow",
    "root": "blue",
}

ROLE_LABEL = {
    "leaf": "Server Cert",
    "intermediate": "Intermediate",
    "root": "Root CA",
}


def _esc(s: str) -> str:
    """Escape Rich markup special chars in user-supplied strings."""
    return s.replace("[", r"\[").replace("]", r"\]")


def render(analysis: dict, verified_ok: bool) -> None:
    host = analysis["host"]
    certs = analysis["certs"]
    extra_certs = analysis["extra_certs"]
    chain_complete = analysis["chain_complete"]
    missing = analysis["missing_cert"]
    missing_aki = analysis.get("missing_aki")
    missing_aia = analysis.get("missing_aia_issuers", [])

    # Header
    status_color = "green" if verified_ok else "red"
    status_text = "TRUSTED" if verified_ok else "NOT TRUSTED"
    console.print()
    console.print(Panel(
        f"[bold]{_esc(host)}[/bold]  —  [{status_color}]{status_text}[/{status_color}]",
        title="[bold cyan]SSL Trust Chain Analysis[/bold cyan]",
        border_style="cyan",
    ))

    for entry in certs:
        role = entry["role"]
        color = ROLE_COLOR[role]
        label = ROLE_LABEL[role]

        if entry["from_server"] and entry["trusted_locally"]:
            source = "[green]server + trust store[/green]"
        elif entry["from_server"]:
            source = "[yellow]server[/yellow]"
        elif entry["trusted_locally"]:
            source = "[blue]local trust store[/blue]"
        else:
            source = "[red]unknown[/red]"

        exp_text = (
            f"[red]EXPIRED {abs(entry['days_remaining'])} days ago[/red]"
            if entry["expired"]
            else f"[green]valid {entry['days_remaining']} days[/green]"
        )

        # Self-signed vs cross-cert label — only meaningful for root-role certs
        type_note = ""
        if role == "root":
            if entry["self_signed"]:
                type_note = " [dim](self-signed trust anchor)[/dim]"
            elif entry["aki"] and entry["aki"] != entry["ski"]:
                type_note = f" [dim](cross-cert, signed by {_esc(entry['issuer_cn'])})[/dim]"

        rows = [
            f"  [dim]Subject :[/dim] [bold {color}]{_esc(entry['cn'])}[/bold {color}]{type_note}",
            f"  [dim]Issuer  :[/dim] {_esc(entry['issuer_cn'])}",
            f"  [dim]Source  :[/dim] {source}",
            f"  [dim]Key     :[/dim] [dim]{entry['key']}[/dim]",
            f"  [dim]Expires :[/dim] {exp_text}",
            f"  [dim]Valid   :[/dim] [dim]{entry['not_before'].strftime('%Y-%m-%d')} → {entry['not_after'].strftime('%Y-%m-%d')}[/dim]",
        ]
        if entry["sans"]:
            sans_str = ", ".join(_esc(s) for s in entry["sans"][:6])
            if len(entry["sans"]) > 6:
                sans_str += f" (+{len(entry['sans'])-6} more)"
            rows.append(f"  [dim]SANs    :[/dim] [dim]{sans_str}[/dim]")
        rows.append(f"  [dim]Serial  :[/dim] [dim]{entry['serial']}[/dim]")
        if entry["ski"]:
            rows.append(f"  [dim]SKI     :[/dim] [dim]{entry['ski']}[/dim]")
        if entry["aki"]:
            rows.append(f"  [dim]AKI     :[/dim] [dim]{entry['aki']}[/dim]")
        for url in entry["aia_issuers"]:
            rows.append(f"  [dim]AIA     :[/dim] [dim]{_esc(url)}[/dim]")
        rows.append(f"  [dim]SHA-256 :[/dim] [dim]{entry['fingerprint'][:47]}…[/dim]")

        console.print(Panel(
            "\n".join(rows),
            title=f"[{color}][{entry['index']+1}] {label}[/{color}]",
            border_style=color,
            padding=(0, 1),
        ))
        if entry["index"] < len(certs) - 1:
            console.print("    [dim]↓  signed by →[/dim]")

    # Chain status
    console.print()
    if chain_complete:
        if missing:
            console.print(f"[green]✓ Chain complete[/green] [dim]({_esc(missing)})[/dim]")
        else:
            console.print("[green]✓ Chain complete — root CA included[/green]")
    else:
        console.print("[red]✗ Chain INCOMPLETE[/red]")
        if missing:
            console.print(f"  [red]Missing issuer:[/red] {_esc(missing)}")
        if missing_aki:
            console.print(f"  [dim]Missing cert SKI:[/dim] [yellow]{missing_aki}[/yellow]")
        for url in missing_aia:
            console.print(f"  [dim]Download from  :[/dim] [cyan]{_esc(url)}[/cyan]")
        if missing_aia:
            console.print()
            console.print("  [dim]Tip — if there are two certs with the same Subject/SKI:[/dim]")
            console.print("  [dim]  • Self-signed (no AKI)   = trust anchor, needs to be in client's trust store[/dim]")
            console.print("  [dim]  • Cross-cert  (has AKI)  = use this in your server chain (links to an existing trusted CA)[/dim]")

    if not verified_ok:
        console.print("[red]✗ Certificate verification FAILED — browser will show a warning[/red]")
    else:
        console.print("[green]✓ Certificate verifies successfully against certifi trust store[/green]")

    if extra_certs:
        console.print()
        console.print(f"[yellow]⚠ Server sent {len(extra_certs)} extra certificate(s) not on the valid path (misconfiguration):[/yellow]")
        for e in extra_certs:
            exp = "[red]EXPIRED[/red]" if e["expired"] else f"valid {e['days_remaining']}d"
            console.print(f"  [dim]• {_esc(e['cn'])}  (issuer: {_esc(e['issuer_cn'])}, {e['key']}, {exp})[/dim]")

    console.print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] sslcheck.py <domain> [port]")
        console.print("  Example: sslcheck.py example.com")
        console.print("  Example: sslcheck.py example.com 8443")
        sys.exit(1)

    host = sys.argv[1].strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    console.print(f"\n[dim]Connecting to {host}:{port} …[/dim]")
    try:
        certs, verified_ok, server_subjects, extra = fetch_chain(host, port)
    except socket.timeout:
        console.print(f"[red]Connection timed out: {host}:{port}[/red]")
        sys.exit(2)
    except ConnectionRefusedError:
        console.print(f"[red]Connection refused: {host}:{port}[/red]")
        sys.exit(2)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(2)

    if not certs:
        console.print("[red]No certificates received from server.[/red]")
        sys.exit(2)

    analysis = analyse_chain(certs, host, server_subjects, extra)
    render(analysis, verified_ok)


if __name__ == "__main__":
    main()
