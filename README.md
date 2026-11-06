<p align="center"><img src="docs/assets/logo.png" alt="notary logo" width="140"></p>

# notary

Command-line tool that inspects the Spanish national eID (DNIe, `info`), signs documents producing standard CAdES-T signatures with RFC 3161 timestamps (`sign`), and verifies signatures made by itself, by a second signer, or by official tools such as AutoFirma (`verify`).

> **Status:** all three commands are implemented (`info`; `sign` with a DNIe or a software signer; `verify` with X.509 chain validation, RFC 3161 timestamp checks, `--at` time evaluation and OCSP revocation checking), plus CAdES-LT (`--ltv`), parallel co-signatures (`cosign`) and PAdES (signing inside a PDF). 143 unit tests cover them.
>
> **Disclaimer:** `notary` is an educational implementation. It has not been audited or certified and makes no claim of legal validity. For official procedures use AutoFirma or another qualified tool.

> **Documentation:**
> - **Authors:** Nacho Pola ([@NachoPola16](https://github.com/NachoPola16)) · Martín Longares Gil ([@martin05mlg](https://github.com/martin05mlg)), equal contribution.
> - **Design document and "What a timestamp proves":** [docs/DESIGN.md](docs/DESIGN.md)
> - **Roadmap:** [ROADMAP.md](ROADMAP.md)
> - **Testing with a real DNIe:** [docs/PRUEBAS_DNIE.md](docs/PRUEBAS_DNIE.md) is a step-by-step guide (setup, every command with its expected result, cases that must fail).
>
> The design and testing documents, and the CLI messages (for example `VEREDICTO: VALID`), are currently in Spanish.

## Requirements

- Python 3.12 or later.
- OpenSC (PKCS#11 module) and a USB DNIe reader, or DNIe Remote (phone with NFC).
- AutoFirma, to check interoperability of the `.csig` files.

| | Windows | macOS | Linux (Debian/Ubuntu) |
|---|---|---|---|
| Python | installer from python.org (tick *Add to PATH*) | `brew install python` | `apt install python3-venv` |
| OpenSC | `.msi` from the OpenSC releases on GitHub | `brew install opensc` | `apt install opensc pcscd` |
| PKCS#11 module | `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll` (or `C:\Windows\System32\DNIeRemotePKCS11.dll`) | `$(brew --prefix)/lib/pkcs11/opensc-pkcs11.so` | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |

Before signing with the card, check that the reader detects the DNIe (neither command asks for the PIN):

```
pkcs11-tool --list-slots
pkcs11-tool --list-objects --type cert
```

## Installation

```
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS, Linux
pip install -e .
```

`pip install -e .` installs the dependencies (`PyKCS11`, `asn1crypto`, `cryptography`, `requests`, and `pypdf`, the latter only to read PDF structure) and creates the `notary` executable. You can also run `python -m notary ...` from the repository root.

## Usage

```
notary info   [--module PATH]
notary sign   <file> [--format detached|attached|pades] [--tsa URL ...] [--out FILE] [--module PATH] [--key KEY.pem --cert CERT.pem] [--no-timestamp]
notary verify <proof.csig> [--content FILE] [--trust FILE ...] [--at TIME]
notary cosign <proof.csig> <file> [--tsa URL ...] [--out FILE] [--module PATH] [--key KEY.pem --cert CERT.pem] [--ltv [--chain CERT ...]]
```
`sign` and `cosign` also accept `--ltv [--chain CERT ...]` (see below).

### 1. Card diagnostics (`notary info`)
- Lists PKCS#11 readers and slots, shows the PIN security flags (`USER_PIN_FINAL_TRY`, `USER_PIN_LOCKED`, etc.) and reads the card's public certificates in a session without login (**it never asks for the PIN**).
- Identifies `CertFirmaDigital` (`content_commitment` / `non_repudiation`) and `CertAutenticacion` (`digital_signature`) from the `KeyUsage` extension.

### 2. CAdES-T signing (`notary sign`)
- **With the DNIe (default):** automatically selects `CertFirmaDigital`, checks before asking for the PIN that `CKF_USER_PIN_FINAL_TRY` and `CKF_USER_PIN_LOCKED` are not set, reads the PIN with `getpass` (no echo, no automatic retries) and asks the chip to sign the SHA-256 `DigestInfo` of the signed attributes (`SET OF`, `0x31`).
- **With the development software signer (`--key` and `--cert`):** lets you develop and run tests without the physical card.
- **RFC 3161 timestamp:** requested over `SHA-256(signatureValue)` with a random 64-bit `nonce` and `certReq=True`, trying in order ACCV (`tss.accv.es`), `freetsa.org`, DigiCert, Sectigo, GlobalSign and Certum (or the URLs given with `--tsa`). If no TSA answers, `sign` fails and **never writes a signature without a timestamp**.
- **`--no-timestamp` (development only):** produces CAdES-BES without a timestamp and prints a warning that `signingTime` is only a claim by the signer.

Examples:
```
# Sign with the DNIe (CAdES-T detached)
notary sign document.pdf

# Sign with local test credentials (CAdES-T attached)
notary sign document.pdf --format attached --key tools/test_certs/signer.key --cert tools/test_certs/signer.crt
```

### 2 pre. PIN protection (`notary pin-guard`)
The DNIe locks after 3 consecutive wrong PINs and, with OpenSC, **the remaining attempts cannot be queried** (the `USER_PIN_FINAL_TRY` flag is unreliable). So `notary` counts failures itself and, after 2 in a row, **refuses to ask for the PIN**. It stores only a per-card counter, never the PIN.
```
notary pin-guard              # show the counter
notary pin-guard --set 2      # set the counter if you know how many attempts were used
notary pin-guard --reset      # reset it (after a correct PIN outside notary, or after using a PIN unlock kiosk)
```
It only counts attempts made with `notary`; if you doubt the PIN, check it at an official DNIe update point instead of guessing.

### 2 bis. Extras: long-term validation (`--ltv`) and multiple signatures (`cosign`)
- **`notary sign doc.pdf --ltv`** (CAdES-LT): after the timestamp, embeds in the signature the signer's certificate chain and an OCSP response. The chain is downloaded from the certificate's AIA (`caIssuers`); with `--chain CERT ...` you can supply the issuers by hand (needed with the test CA). If the evidence cannot be gathered, `sign` fails and writes nothing. `verify` uses that response **offline**, as long as it was produced after the timestamp.
- **`notary cosign proof.csig doc.pdf`**: adds a second parallel signature (another DNIe or the software signer) with its own timestamp, without touching the original (writes `proof.multi.csig` by default). `verify` shows every signer and the final verdict is the worst of all.

### 2 ter. PAdES: signing inside a PDF (`--format pades`)
```
notary sign contract.pdf --format pades        # writes contract.signed.pdf
notary verify contract.signed.pdf --trust ACRaiz2.crt AC006.crt <TSA root>
```
- The signature is added as an **incremental update**: the original PDF bytes are untouched and a signature, an invisible signature field and a new cross-reference table are appended. The signature (`/SubFilter /ETSI.CAdES.detached`) covers the whole file except the `/Contents` value (`/ByteRange`) and carries a timestamp (PAdES-B-T).
- To add **another signer**, just sign the already signed PDF again; earlier signatures stay valid. `verify` shows each signature and the final verdict is the worst of all.
- Works with classic and modern PDFs (xref streams and object streams). Encrypted PDFs are not supported.
- `--format pades` cannot be combined with `--ltv` or `cosign`. The signature is invisible: a PDF reader shows it in its signatures panel, not on the page.

### 3. Verification (`notary verify`)
Verifies step by step a `.csig` file (`detached` or `attached`, your own, a second signer's or AutoFirma's) or a signed PDF (PAdES; if the file starts with `%PDF-`, all its signatures are verified) and prints `VEREDICTO: VALID` (exit code `0`), `VEREDICTO: INVALID` (`1`) or `VEREDICTO: INDETERMINATE` (`2`):
1. CMS `SignedData` structure, and consistency of `detached`/`attached` mode with `--content`.
2. Document digest against `messageDigest`.
3. Signer certificate and its match with `signingCertificateV2` (or `signingCertificate`).
4. Mathematical RSA/ECDSA signature over `signedAttrs` encoded as `SET OF` (`0x31`).
5. X.509 certification path up to an anchor given with `--trust`.
6. RFC 3161 timestamp token (`messageImprint == Hash(signatureValue)`, the TSA's CMS signature, `ExtendedKeyUsage = timeStamping`, and the TSA chain up to `--trust`). If the file has no timestamp, it warns that the only time is a claim.
7. Certificate validity at the TSA time (or at the ISO 8601 instant given with `--at`).
8. Revocation status via **OCSP**, dynamically extracting the URL from the certificate's AIA extension (`AuthorityInformationAccess`). The request carries a nonce and the response must be current (`thisUpdate`–`nextUpdate`). If the signature carries an embedded OCSP response (`--ltv`), that one is used, offline.

Example:
```
notary verify document.pdf.csig --content document.pdf --trust ACRaiz2.crt AC006.crt freetsa_root.crt
```

## Helper tools (`tools/`)

- **Generate a test CA and certificates (including a short-lived certificate):**
  ```
  python -m tools.generate_test_ca
  ```
- **Generate a batch of 6 test proofs (2 valid, 4 defective) with an answer key**, useful to test a verifier against known-bad inputs:
  ```
  # From a real signature made with the DNIe:
  python -m tools.forger --base-proof doc.pdf.csig --base-content doc.pdf --output-dir pair_exchange

  # Or in standalone self-test mode, with no card and no network:
  python -m tools.forger --self-test --output-dir pair_exchange_test
  ```

## Automated tests

```
python -m unittest discover -s tests -t . -v
```

The 143 tests cover the CAdES builder, the TSA client, the CLI, PKCS#11 detection, `PKCS11Signer`, the full verifier (chains, TSA token, expiry at TSA time / `--at`, OCSP with nonce and freshness, LTV evidence, multiple signatures, PAdES, robustness against corrupted files) and the `forger.py` generator, with no DNIe and no network needed.

## Checking a signature with OpenSSL (by hand)

```
openssl cms -verify -binary -inform DER -in doc.csig -content doc -CAfile tools/test_certs/test_ca.crt
```

`-binary` is required for `detached` signatures: without it, some OpenSSL builds on Windows treat the document as text and fail even though the signature is correct.

## Privacy

Signatures made with the DNIe contain your full name and ID number. Do not commit real signatures to git; for tests use the test CA (`tools/generate_test_ca.py`).

## License

[MIT](LICENSE).
