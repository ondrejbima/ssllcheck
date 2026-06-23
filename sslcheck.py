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
import urllib.request
import warnings
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID
from cryptography.x509 import ocsp as x509_ocsp
from cryptography.hazmat.primitives.serialization import Encoding as CertEncoding
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(emoji=False)


# ---------------------------------------------------------------------------
# Trust store helpers
# ---------------------------------------------------------------------------

def _load_trusted_certs() -> dict[bytes, x509.Certificate]:
    """Load certifi CA bundle, keyed by subject DER bytes."""
    trusted: dict[bytes, x509.Certificate] = {}
    pem_data = Path(certifi.where()).read_bytes()
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


def cert_aia_ocsp(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        return [
            str(ad.access_location.value)
            for ad in ext.value
            if ad.access_method == AuthorityInformationAccessOID.OCSP
        ]
    except x509.ExtensionNotFound:
        return []


def cert_crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        urls = []
        for dp in ext.value:
            if dp.full_name:
                for gn in dp.full_name:
                    if hasattr(gn, "value") and isinstance(gn.value, str):
                        urls.append(gn.value)
        return urls
    except x509.ExtensionNotFound:
        return []


# ---------------------------------------------------------------------------
# AIA certificate fetching and OCSP checking
# ---------------------------------------------------------------------------

def check_ocsp(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    """
    Check OCSP revocation status of cert against issuer.
    Returns 'good', 'revoked', 'unknown', 'no-ocsp', or 'error'.
    """
    urls = cert_aia_ocsp(cert)
    if not urls:
        return "no-ocsp"
    try:
        req = (
            x509_ocsp.OCSPRequestBuilder()
            .add_certificate(cert, issuer, hashes.SHA256())
            .build()
        )
        http_req = urllib.request.Request(
            urls[0],
            data=req.public_bytes(CertEncoding.DER),
            method="POST",
            headers={"Content-Type": "application/ocsp-request"},
        )
        with urllib.request.urlopen(http_req, timeout=10) as r:
            resp = x509_ocsp.load_der_ocsp_response(r.read())
        if resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
            cs = resp.certificate_status
            if cs == x509_ocsp.OCSPCertStatus.GOOD:
                return "good"
            if cs == x509_ocsp.OCSPCertStatus.REVOKED:
                return "revoked"
            return "unknown"
    except Exception:
        pass
    return "error"


def check_crl(cert: x509.Certificate) -> str:
    """Check CRL revocation. Returns 'good', 'revoked', 'no-crl', or 'error'."""
    urls = cert_crl_urls(cert)
    if not urls:
        return "no-crl"
    try:
        with urllib.request.urlopen(urls[0], timeout=10) as r:
            data = r.read(4 * 1024 * 1024)  # cap at 4 MB
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                crl = x509.load_der_x509_crl(data)
            except Exception:
                crl = x509.load_pem_x509_crl(data)
        return "revoked" if crl.get_revoked_certificate_by_serial_number(cert.serial_number) else "good"
    except Exception:
        return "error"


def check_revocation(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    """Try OCSP first, fall back to CRL. Returns 'good', 'revoked', 'unknown', 'no-crl', or 'error'."""
    result = check_ocsp(cert, issuer)
    if result in ("good", "revoked", "unknown"):
        return result
    return check_crl(cert)


def _fetch_aia_cert(url: str) -> x509.Certificate | None:
    """Download and decode a cert from an AIA CA Issuers URL (DER or PEM)."""
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = r.read()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                return x509.load_der_x509_certificate(data)
            except Exception:
                return x509.load_pem_x509_certificate(data)
    except Exception:
        return None


def _build_aia_chain(
    base: list[x509.Certificate],
    server_subjects: set[bytes],
) -> tuple[list[x509.Certificate], list[str]] | None:
    """
    When base ends at an untrusted self-signed root, follow AIA CA Issuers
    of the penultimate cert to find a cross-signed alternative.
    Returns (alt_chain, sources) where sources are "server"/"aia_download"/"trust_store",
    or None if no trusted alternative is found.
    """
    if len(base) < 2:
        return None

    def _src(cert: x509.Certificate) -> str:
        if cert.subject.public_bytes() in server_subjects:
            return "server"
        if is_trusted(cert):
            return "trust_store"
        return "aia_download"

    penultimate = base[-2]
    for url in cert_aia_issuers(penultimate):
        cross = _fetch_aia_cert(url)
        if cross is None:
            continue
        if cross.subject.public_bytes() != penultimate.issuer.public_bytes():
            continue
        # Skip if same problem: self-signed and not trusted
        if is_self_signed(cross) and not is_trusted(cross):
            continue

        alt = list(base[:-1]) + [cross]
        alt_sources = [_src(c) for c in base[:-1]] + ["aia_download"]
        current = cross

        for _ in range(5):
            if is_trusted(current) or is_self_signed(current):
                break
            ik = current.issuer.public_bytes()
            if ik in TRUSTED:
                alt.append(TRUSTED[ik])
                alt_sources.append("trust_store")
                break
            found = False
            for aurl in cert_aia_issuers(current):
                nc = _fetch_aia_cert(aurl)
                if nc and nc.subject.public_bytes() == ik:
                    alt.append(nc)
                    alt_sources.append("aia_download")
                    current = nc
                    found = True
                    break
            if not found:
                break

        return alt, alt_sources

    return None


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


def _verify_tls(host: str, port: int) -> tuple[bool, str | None]:
    """Return (verified, reason) where reason is None if verified, else human-readable error."""
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, str(e)


def fetch_chain(host: str, port: int = 443) -> tuple[
    list[x509.Certificate],
    bool,
    set[bytes],
    list[x509.Certificate],
    bool,
    list[str],
    list[x509.Certificate] | None,
    list[str] | None,
    str | None,
]:
    """
    Returns (ordered, verified_ok, server_subjects, extra, order_wrong,
             server_path_cns, alt_chain, alt_chain_sources, verify_error).
    ordered[0] is the leaf certificate.
    server_subjects: subject DER bytes of certs actually sent by the server.
    extra: server certs not on the valid path.
    order_wrong: True if server sent path certs in wrong order.
    server_path_cns: CNs of path certs in server-sent order (for wrong-order display).
    alt_chain / alt_chain_sources: alternative trusted path via AIA, or None.
    verify_error: reason for TLS verification failure, or None if verified OK.
    """
    server_pem_blocks = _fetch_server_chain(host, port)
    if not server_pem_blocks:
        raise RuntimeError("openssl s_client returned no certificates")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        server_certs = [x509.load_pem_x509_certificate(p) for p in server_pem_blocks]
    server_subjects: set[bytes] = {c.subject.public_bytes() for c in server_certs}

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

    # Detect wrong order — compare only certs the server actually sent (exclude trust-store additions)
    path_subjects = {c.subject.public_bytes() for c in ordered}
    server_path_order = [c.subject.public_bytes() for c in server_certs
                         if c.subject.public_bytes() in path_subjects]
    our_path_order = [c.subject.public_bytes() for c in ordered
                      if c.subject.public_bytes() in path_subjects
                      and c.subject.public_bytes() in server_subjects]
    order_wrong = server_path_order != our_path_order
    server_path_cns = [cert_cn(by_subject[s]) for s in server_path_order if s in by_subject]

    verified_ok, verify_error = _verify_tls(host, port)

    # AIA chain discovery when chain ends at untrusted self-signed root
    alt_chain: list[x509.Certificate] | None = None
    alt_chain_sources: list[str] | None = None
    if not verified_ok and ordered and is_self_signed(ordered[-1]) and not is_trusted(ordered[-1]):
        console.print("[dim]  Trying AIA chain discovery…[/dim]")
        aia_result = _build_aia_chain(ordered, server_subjects)
        if aia_result:
            alt_chain, alt_chain_sources = aia_result

    return ordered, verified_ok, server_subjects, extra, order_wrong, server_path_cns, alt_chain, alt_chain_sources, verify_error


# ---------------------------------------------------------------------------
# Chain analysis
# ---------------------------------------------------------------------------

def analyse_chain(
    certs: list[x509.Certificate],
    host: str,
    server_subjects: set[bytes],
    extra: list[x509.Certificate],
    order_wrong: bool,
    server_path_cns: list[str],
    alt_chain: list[x509.Certificate] | None = None,
    alt_chain_sources: list[str] | None = None,
    verify_error: str | None = None,
) -> dict:
    """
    Returns structured analysis of the chain.
    certs: ordered leaf → root (valid path).
    server_subjects: subject DER bytes of certs actually sent by the server.
    extra: certs sent by server that are NOT part of the valid path.
    order_wrong: server sent path certs in wrong order.
    server_path_cns: CNs of path certs in server-sent order.
    alt_chain / alt_chain_sources: alternative path from AIA discovery.
    verify_error: TLS verification error message, if any.
    """

    result = {
        "host": host,
        "certs": [],
        "extra_certs": [],
        "chain_complete": False,
        "missing_cert": None,
        "order_wrong": order_wrong,
        "server_path_cns": server_path_cns,
        "contains_anchor": False,
        "anchor_not_trusted": False,
        "trust_failure_reason": None,
        "verify_error": verify_error,
        "alt_chain_certs": [],
        "alt_chain_trusted": False,
    }

    for i, cert in enumerate(certs):
        role = "leaf" if i == 0 else ("root" if (is_self_signed(cert) or is_trusted(cert)) else "intermediate")
        from_server = cert.subject.public_bytes() in server_subjects
        trusted_locally = is_trusted(cert)

        # Revocation check (OCSP → CRL fallback); last cert in chain is the self-signed root
        ocsp_status = "—"
        if i + 1 < len(certs):
            ocsp_status = check_revocation(cert, certs[i + 1])

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
            "ocsp_status": ocsp_status,
        }
        result["certs"].append(entry)

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

    # Detect anchor in server chain: self-signed cert sent by server (not just added locally)
    for cert in certs[1:]:
        if is_self_signed(cert) and cert.subject.public_bytes() in server_subjects:
            result["contains_anchor"] = True
            break

    if certs:
        last = certs[-1]
        if is_self_signed(last):
            result["chain_complete"] = True
            if not is_trusted(last):
                result["anchor_not_trusted"] = True
                result["trust_failure_reason"] = (
                    f"Root CA '{cert_cn(last)}' is self-signed but NOT in any trust store. "
                    f"Serve the cross-signed variant instead (same SKI, different issuer with AKI present)."
                )
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

    result["has_revoked"] = any(e.get("ocsp_status") == "revoked" for e in result["certs"])

    # Alternative chain from AIA discovery
    if alt_chain and alt_chain_sources:
        alt_entries = []
        for i, (cert, src) in enumerate(zip(alt_chain, alt_chain_sources)):
            role = "leaf" if i == 0 else ("root" if (is_self_signed(cert) or is_trusted(cert)) else "intermediate")
            alt_entries.append({
                "index": i,
                "role": role,
                "cn": cert_cn(cert),
                "issuer_cn": cert_issuer_cn(cert),
                "source": src,
                "trusted_locally": is_trusted(cert),
                "aia_issuers": cert_aia_issuers(cert),
            })
        result["alt_chain_certs"] = alt_entries
        result["alt_chain_trusted"] = any(
            e["trusted_locally"] for e in alt_entries if e["role"] == "root"
        )

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
    order_wrong = analysis.get("order_wrong", False)
    server_path_cns = analysis.get("server_path_cns", [])
    contains_anchor = analysis.get("contains_anchor", False)
    anchor_not_trusted = analysis.get("anchor_not_trusted", False)
    trust_failure_reason = analysis.get("trust_failure_reason")
    alt_chain_certs = analysis.get("alt_chain_certs", [])
    alt_chain_trusted = analysis.get("alt_chain_trusted", False)
    has_revoked = analysis.get("has_revoked", False)

    # Header
    if has_revoked and verified_ok:
        status_color, status_text = "red", "REVOKED CERT IN CHAIN"
    elif verified_ok:
        status_color, status_text = "green", "TRUSTED"
    else:
        status_color, status_text = "red", "NOT TRUSTED"
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
                type_note = " [dim](self-signed)[/dim]"
            elif entry["aki"] and entry["aki"] != entry["ski"]:
                type_note = " [dim](cross-cert)[/dim]"

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", no_wrap=True)
        grid.add_column(no_wrap=False, ratio=3)
        grid.add_column(style="dim", no_wrap=True)
        grid.add_column(no_wrap=False, ratio=3)

        date_range = f"[dim]{entry['not_before'].strftime('%Y-%m-%d')} → {entry['not_after'].strftime('%Y-%m-%d')}[/dim]"

        grid.add_row("Subject :", f"[bold {color}]{_esc(entry['cn'])}[/bold {color}]",
                     "Issuer  :", _esc(entry["issuer_cn"]))
        if type_note:
            grid.add_row("Type    :", type_note.strip(), "", "")
        grid.add_row("Source  :", source,           "Key     :", f"[dim]{entry['key']}[/dim]")
        grid.add_row("Expires :", exp_text,         "Valid   :", date_range)
        grid.add_row("Serial  :", f"[dim]{entry['serial']}[/dim]",
                     "SHA-256 :", f"[dim]{entry['fingerprint'][:29]}…[/dim]")

        if entry["ski"] or entry["aki"]:
            grid.add_row(
                "SKI     :", f"[dim]{entry['ski'] or '—'}[/dim]",
                "AKI     :", f"[dim]{entry['aki'] or '—'}[/dim]",
            )

        revoc = entry.get("ocsp_status", "—")
        if revoc == "good":
            revoc_cell = "[green]✓ good[/green]"
        elif revoc == "revoked":
            revoc_cell = "[bold red]✗ REVOKED[/bold red]"
        elif revoc == "unknown":
            revoc_cell = "[yellow]? unknown[/yellow]"
        elif revoc in ("error", "no-crl", "no-ocsp", "—"):
            revoc_cell = None
        else:
            revoc_cell = f"[dim]{revoc}[/dim]"
        aia_urls = entry["aia_issuers"]
        aia_start = 0
        if revoc_cell:
            if aia_urls:
                grid.add_row("Revoc.  :", revoc_cell, "AIA     :", f"[dim]{_esc(aia_urls[0])}[/dim]")
                aia_start = 1
            else:
                grid.add_row("Revoc.  :", revoc_cell, "", "")

        if entry["sans"]:
            sans_str = ", ".join(_esc(s) for s in entry["sans"][:6])
            if len(entry["sans"]) > 6:
                sans_str += f" (+{len(entry['sans'])-6} more)"
            grid.add_row("SANs    :", f"[dim]{sans_str}[/dim]", "", "")

        for url in aia_urls[aia_start:]:
            grid.add_row("AIA     :", f"[dim]{_esc(url)}[/dim]", "", "")

        is_bad = entry.get("ocsp_status") == "revoked" or entry["expired"]
        border_color = "red" if is_bad else color
        console.print(Panel(
            grid,
            title=f"[{border_color}][{entry['index']+1}] {label}[/{border_color}]",
            border_style=border_color,
            padding=(0, 1),
        ))
        if entry["index"] < len(certs) - 1:
            console.print("    [dim]↓  signed by →[/dim]")

    # Chain status
    console.print()
    if chain_complete and not anchor_not_trusted:
        if missing:
            console.print(f"[green]✓ Chain complete[/green] [dim]({_esc(missing)})[/dim]")
        else:
            console.print("[green]✓ Chain complete — root CA included[/green]")
    elif chain_complete and anchor_not_trusted:
        console.print("[yellow]~ Chain structurally complete but root CA not trusted[/yellow]")
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
            console.print("  [dim]Tip — if two certs share the same Subject/SKI:[/dim]")
            console.print("  [dim]  • Self-signed (no AKI)  = trust anchor, must be in client trust store[/dim]")
            console.print("  [dim]  • Cross-cert  (has AKI) = use this in server chain (chains to existing trusted CA)[/dim]")

    if has_revoked:
        console.print("[bold red]✗ REVOKED cert in chain — browsers doing CRL/OCSP checks will reject this[/bold red]")
        for i, entry in enumerate(certs):
            if entry.get("ocsp_status") == "revoked":
                console.print(f"  [red]Revoked:[/red] {_esc(entry['cn'])}  serial {_esc(entry['serial'])}")
                if i > 0:
                    for url in certs[i - 1].get("aia_issuers", []):
                        console.print(f"  [green]Replace with fresh download from:[/green] [cyan]{_esc(url)}[/cyan]")
                        console.print("  [dim](curl -o new.der <url> && openssl x509 -inform DER -in new.der -out new.pem)[/dim]")
                        break

    if not verified_ok:
        console.print("[red]✗ Certificate verification FAILED — browser will show a warning[/red]")
        if trust_failure_reason:
            console.print(f"  [red]Reason:[/red] {_esc(trust_failure_reason)}")
        elif analysis.get("verify_error"):
            console.print(f"  [red]Error:[/red] {_esc(analysis['verify_error'])}")
    elif not has_revoked:
        console.print("[green]✓ Certificate verifies successfully against certifi trust store[/green]")

    # Server chain issues
    issues: list[str] = []
    if order_wrong:
        issues.append("[yellow]Incorrect order[/yellow] — server sent chain certs out of sequence (tool reordered for display)")
    if contains_anchor:
        issues.append("[yellow]Contains anchor[/yellow] — server unnecessarily includes the root CA; only leaf + intermediates needed")
    if extra_certs:
        issues.append(f"[yellow]Extra certs[/yellow] — {len(extra_certs)} unrelated certificate(s) sent by server")

    if issues:
        console.print()
        console.print("[bold yellow]Server chain issues:[/bold yellow]")
        if order_wrong:
            console.print(f"  • [yellow]Incorrect order[/yellow] — server sent chain certs out of sequence (tool reordered for display)")
            if server_path_cns:
                server_str = " → ".join(_esc(cn) for cn in server_path_cns)
                correct_cns = [entry["cn"] for entry in certs if entry["from_server"]]
                correct_str = " → ".join(_esc(cn) for cn in correct_cns)
                console.print(f"    [dim]Server sent:   {server_str}[/dim]")
                console.print(f"    [dim]Correct order: [green]{correct_str}[/green][/dim]")
        if contains_anchor:
            console.print(f"  • [yellow]Contains anchor[/yellow] — server unnecessarily includes the root CA; only leaf + intermediates needed")
        if extra_certs:
            console.print(f"  • [yellow]Extra certs[/yellow] — {len(extra_certs)} unrelated certificate(s) sent by server")
            for e in extra_certs:
                exp = "[red]EXPIRED[/red]" if e["expired"] else f"valid {e['days_remaining']}d"
                console.print(f"    [dim]- {_esc(e['cn'])}  (issuer: {_esc(e['issuer_cn'])}, {e['key']}, {exp})[/dim]")

    # Alternative trusted path discovered via AIA
    if alt_chain_certs:
        trust_label = "[green]TRUSTED[/green]" if alt_chain_trusted else "[red]NOT TRUSTED[/red]"
        console.print()
        console.print(Panel(
            "[dim]Browsers can use AIA to download missing intermediates and find this alternative path.[/dim]",
            title=f"[blue]Alternative trust path (AIA discovery) — {trust_label}[/blue]",
            border_style="blue",
            padding=(0, 1),
        ))

        src_labels = {
            "server": "[yellow]server[/yellow]",
            "aia_download": "[cyan]AIA download[/cyan]",
            "trust_store": "[blue]trust store[/blue]",
        }

        prev_aia_urls: list[str] = []
        for entry in alt_chain_certs:
            role = entry["role"]
            color = ROLE_COLOR[role]
            src = src_labels.get(entry["source"], entry["source"])
            trust_mark = "  [green]← trusted root[/green]" if (entry["trusted_locally"] and role == "root") else ""
            download_note = ""
            if entry["source"] == "aia_download" and prev_aia_urls:
                download_note = f"  [dim]({_esc(prev_aia_urls[0])})[/dim]"
            console.print(f"  [{color}]{entry['index']+1}. {_esc(entry['cn'])}[/{color}]  ({src}){trust_mark}{download_note}")
            prev_aia_urls = entry["aia_issuers"]
            if entry["index"] < len(alt_chain_certs) - 1:
                console.print("     [dim]↓[/dim]")

        if alt_chain_trusted:
            aia_entries = [e for e in alt_chain_certs if e["source"] == "aia_download"]
            for ae in aia_entries:
                idx = ae["index"]
                if idx > 0:
                    prev = alt_chain_certs[idx - 1]
                    for url in prev["aia_issuers"]:
                        console.print()
                        console.print("  [green]Fix:[/green] Replace the self-signed root CA in your server config with the cross-signed variant:")
                        console.print(f"  [cyan]{_esc(url)}[/cyan]")
                        console.print("  [dim](The downloaded cert will have AKI present — that confirms it's the cross-signed variant)[/dim]")
                        break

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
        certs, verified_ok, server_subjects, extra, order_wrong, server_path_cns, alt_chain, alt_chain_sources, verify_error = fetch_chain(host, port)
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

    analysis = analyse_chain(
        certs, host, server_subjects, extra, order_wrong,
        server_path_cns, alt_chain, alt_chain_sources, verify_error,
    )
    render(analysis, verified_ok)


if __name__ == "__main__":
    main()
