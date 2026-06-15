# sslcheck.py — SSL Trust Chain Checker

A mini SSLLabs alternative for the command line. Connects to a host, fetches the full certificate chain, and gives a detailed trust analysis without any external API.

## Installation

```bash
pip install -r requirements.txt
```

> Requires Python 3.11+ and `openssl` available in `PATH`.

## Usage

```bash
python3 sslcheck.py <domain> [port]

python3 sslcheck.py google.com
python3 sslcheck.py example.com 8443
```

## Features

- **Full chain display** — shows every certificate in the chain (leaf → intermediate → root CA) with role labels
- **Trust verification** — checks whether the chain verifies against the [certifi](https://github.com/certifi/python-certifi) trust store (same bundle used by browsers)
- **Certificate details** per cert:
  - Subject / Issuer CN
  - Key algorithm and size (RSA, EC)
  - Validity dates and days remaining (or expiry warning)
  - Serial number and SHA-256 fingerprint
  - Subject Key Identifier (SKI) and Authority Key Identifier (AKI)
  - Subject Alternative Names (SANs) for leaf certs
  - AIA CA Issuers URLs
- **Revocation checking** — OCSP first, CRL fallback; reports `good`, `revoked`, or `unknown`
- **AIA chain discovery** — when the server sends an untrusted self-signed root, follows AIA CA Issuers URLs to find a cross-signed alternative path that browsers would accept
- **Server chain issue detection**:
  - Wrong certificate order
  - Unnecessary root CA inclusion
  - Extra unrelated certificates sent by the server
- **Self-signed vs. cross-cert labelling** — distinguishes trust anchors from cross-signed intermediates
- **Source tagging** — shows whether each cert came from the server, the local trust store, or was downloaded via AIA

## Example output — google.com

```
Connecting to google.com:443 …

╭────────────────────────── SSL Trust Chain Analysis ──────────────────────────╮
│ google.com  —  TRUSTED                                                       │
╰──────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────── [1] Server Cert ───────────────────────────────╮
│ Subject :  *.google.com               Issuer  :  WE2                         │
│ Source  :  server                     Key     :  EC secp256r1 256            │
│ Expires :  valid 62 days              Valid   :  2026-05-25 → 2026-08-17     │
│ Serial  :  5C:0E:53:26:87:04:71:0D:…  SHA-256 :  5A:8E:04:C3:1E:AD:E5:2E:66… │
│ SKI     :  56:98:C1:48:38:98:B5:1F:…  AKI     :  75:BE:C4:77:AE:89:F6:44:37… │
│ Revoc.  :  ✓ good                     AIA     :  http://i.pki.goog/we2.crt   │
│ SANs    :  *.google.com, *.appengine.google.com, *.bdn.dev,                 │
│            *.cloud.google.com, *.crowdsource.google.com (+59 more)           │
╰──────────────────────────────────────────────────────────────────────────────╯
    ↓  signed by →
╭────────────────────────────── [2] Intermediate ──────────────────────────────╮
│ Subject :  WE2                        Issuer  :  GTS Root R4                 │
│ Source  :  server                     Key     :  EC secp256r1 256            │
│ Expires :  valid 980 days             Valid   :  2023-12-13 → 2029-02-20     │
│ Serial  :  7F:F3:2D:6B:40:9D:15:D5:…  SHA-256 :  9C:3F:2F:D1:1C:57:D7:C6:49… │
│ SKI     :  75:BE:C4:77:AE:89:F6:44:…  AKI     :  80:4C:D6:EB:74:FF:49:36:A3… │
│ Revoc.  :  ✓ good                     AIA     :  http://i.pki.goog/r4.crt    │
╰──────────────────────────────────────────────────────────────────────────────╯
    ↓  signed by →
╭──────────────────────────────── [3] Root CA ─────────────────────────────────╮
│ Subject :  GTS Root R4                Issuer  :  GlobalSign Root CA          │
│ Type    :  (cross-cert)                                                      │
│ Source  :  server + trust store       Key     :  EC secp384r1 384            │
│ Expires :  valid 591 days             Valid   :  2023-11-15 → 2028-01-28     │
│ Serial  :  7F:E5:30:BF:33:13:43:BE:…  SHA-256 :  76:B2:7B:80:A5:80:27:DC:3C… │
│ SKI     :  80:4C:D6:EB:74:FF:49:36:…  AKI     :  60:7B:66:1A:45:0D:97:CA:89… │
│ AIA     :  http://i.pki.goog/gsr1.c…                                         │
╰──────────────────────────────────────────────────────────────────────────────╯

✓ Chain complete — root CA included
✓ Certificate verifies successfully against certifi trust store
```
