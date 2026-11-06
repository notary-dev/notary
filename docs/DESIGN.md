# Design document — `notary`

**Authors:** Nacho Pola · Martín Longares Gil

> The CLI output and the source comments are in Spanish; this document describes them in English.

---

## 1. Architecture and formats

### 1.1 Module structure
The `notary` package separates access to the cryptographic hardware, ASN.1/CMS construction, network communication (TSA and OCSP) and the verification engine:

- **Signer interface (`notary/signer/`):**
  - `Signer` (`base.py`): abstract interface with `get_certificate() -> asn1crypto.x509.Certificate` and `sign_hash(digest: bytes) -> bytes`.
  - `SoftwareSigner` (`software_signer.py`): loads a local RSA private key and PEM certificate, checks that their public keys match, and signs 32-byte SHA-256 digests.
  - `PKCS11Signer` (`pkcs11_signer.py`): locates the PKCS#11 module, checks the PIN security flags (`CKF_USER_PIN_LOCKED`, `CKF_USER_PIN_FINAL_TRY`), selects the signing certificate (`CertFirmaDigital`) in a public session, reads the PIN with `getpass` without automatic retries, and sends the `DigestInfo` structure (51 bytes) to the card using `CKM_RSA_PKCS`.
- **CAdES builder (`notary/cades/builder.py`):**
  - Builds a DER-encoded CMS `ContentInfo` (`1.2.840.113549.1.7.2`, `signedData`).
  - Supports `detached` mode (`encapContentInfo.eContent = None`, the document travels separately) and `attached` mode (`encapContentInfo.eContent = OctetString(content)`).
  - Puts the four mandatory attributes in `signedAttrs` (`contentType`, `messageDigest`, `signingTime`, `signingCertificateV2`) and, for CAdES-T, adds the RFC 3161 token as an unsigned attribute (`signatureTimeStampToken`, OID `1.2.840.113549.1.9.16.2.14`).
- **RFC 3161 TSA client (`notary/tsa.py`):**
  - Computes `SHA-256(signatureValue)`, generates a cryptographically random `nonce`, requests `certReq = True`, and walks the configured TSAs in order until one returns a `granted` response whose `messageImprint` and `nonce` match.
- **LTV evidence and multiple signatures (`notary/cades/ltv.py`, `notary/evidence.py`, `add_parallel_signature` in `builder.py`):**
  - `sign --ltv` adds, after the timestamp, two unsigned attributes from ETSI EN 319 122-1: `certificateValues` (signer chain, `1.2.840.113549.1.9.16.2.23`) and `revocationValues` with the OCSP response (`...2.24`). The result is CAdES-LT. The chain comes from `--chain` or is downloaded from the certificate's AIA (`caIssuers`), and the OCSP response is validated before embedding it: if the evidence cannot be gathered, `sign` fails and writes nothing.
  - `cosign` adds a second parallel `SignerInfo` to an existing `.csig`: each signer signs the document on their own and carries their own timestamp. Earlier signatures are preserved byte for byte.
- **Verifier and OCSP client (`notary/verify.py`, `notary/ocsp.py`):**
  - Takes the `.csig` apart and validates document integrity, signed attributes, the mathematical signature, the signer chain up to `--trust`, the RFC 3161 timestamp (imprint, the TSA's CMS signature, `ExtendedKeyUsage = timeStamping`, and the TSA chain up to `--trust`), certificate validity at the TSA time (or `--at`) and OCSP revocation status.

---

## 2. Design questions

### Question 1: the two certificates in the DNIe
> *The DNIe has two certificates. Which one must sign a document, and how does your program tell them apart without relying on their labels?*

The DNIe holds two end-entity certificates issued by the Spanish national police:
1. **`CertFirmaDigital`** (qualified electronic signature certificate): the one to use for signing documents.
2. **`CertAutenticacion`** (authentication certificate): meant to authenticate the holder to servers or sessions (for example TLS client authentication).

`notary` tells them apart by inspecting the standard X.509 **`KeyUsage`** extension (OID `2.5.29.15`, RFC 5280):
- The signing certificate sets the **`non_repudiation`** bit (called **`content_commitment`** in RFC 5280 and in `asn1crypto`/`cryptography`).
- The authentication certificate sets **`digital_signature`** without `non_repudiation`/`content_commitment`.

The PKCS#11 label (`CKA_LABEL`) is only a fallback if some certificate lacks `KeyUsage`. Once the signing certificate is chosen in a public session, its `CKA_ID` is kept to find the matching private key (`CKO_PRIVATE_KEY`) after PIN login.

---

### Question 2: what is sent to the TSA, and why not the document?
> *What exactly do you send to the TSA? Why not the document? What would a token over the document prove, and what would it not prove?*

In CAdES-T the TSA receives the **SHA-256 digest of the signature value (`SignerInfo.signature`)**, never the digest of the original document.

- **What a token over the document would prove:** only that the file existed before the TSA time $T$. It would **not** prove who signed it or when the signature was made: a signer whose key expired or was revoked today could take a document stamped a year ago, sign it today with the expired/revoked key, and attach the old stamp pretending the signature is a year old.
- **What a token over `signatureValue` proves:** `signatureValue` depends cryptographically on the signer's private key and on `signedAttrs` (which contain the document's `messageDigest` and the certificate hash in `signingCertificateV2`). Stamping `SHA-256(signatureValue)` therefore proves that **that specific signature over that document had already been computed no later than $T$**.

---

### Question 3: which bytes does the card actually sign?
> *What bytes does the card actually sign? (Hint: it is not the document, and it is not exactly the DER encoding of the signed attributes as they appear in the file.)*

There are three levels:
1. The `SHA-256` digest of the document is computed and placed in the signed attribute `messageDigest`.
2. Inside the `.csig` file, `signedAttrs` is DER-encoded with the implicit context tag `[0]` (first byte **`0xA0`**). However, per RFC 5652 §5.4, to compute or verify the signature that `[0]` tag (`0xA0`) must be replaced by the universal **`SET OF`** tag (**`0x31`**), keeping the elements in canonical DER order. The `SHA-256` (32 bytes) of that `SET OF` encoding is computed.
3. When `C_Sign` is called on the card with the PKCS#11 mechanism `CKM_RSA_PKCS`, the card receives neither the document nor the bare 32-byte hash, but the 51-byte ASN.1 DER **`DigestInfo`** structure (RFC 8017 §9.2): the 19-byte SHA-256 `AlgorithmIdentifier` (`30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`) followed by the 32-byte digest `SHA-256(SET OF signedAttrs)`. The chip applies PKCS#1 v1.5 type `01` padding and the modular exponentiation with the private key.

---

### Question 4: why is `signingCertificateV2` there, and what attack does it prevent?
> *Why is `signingCertificateV2` there? What attack does it prevent?*

In classic CMS (RFC 5652) the signature covers `signedAttrs`, but the signer's certificate (`SignedData.certificates`) and its reference in `SignerInfo.sid` are **outside** the signed bytes.

Without `signingCertificateV2` (RFC 5035), an attacker or a malicious CA could issue a second certificate with **the same public key** but another identity (`Subject`), policy or key usage, and swap it into the `.csig`. The RSA signature would still verify against the public key. By including the SHA-256 hash of the certificate's full DER bytes in `signingCertificateV2` inside `signedAttrs`, the exact certificate is protected by the signature and any substitution breaks verification.

---

### Question 5: can the certificates inside the `.csig` be trusted?
> *The signature file contains certificates. Can your verifier trust them? Where does trust come from?*

**No.** Anyone can create their own self-signed CA, issue a certificate in someone else's name, sign a document and put the whole chain in `SignedData.certificates`.

Trust never comes from the `.csig`, but from the **trust anchors** the verifier is explicitly given out of band with `--trust` (for example the Spanish police's `AC RAIZ DNIE 2` and the TSA's root certificate). Certificates inside the `.csig` serve only as auxiliary links to build the path from the leaf certificate to an anchor in `--trust`. If the signer or TSA chain does not end in a certificate present in `--trust`, the verifier never returns `VALID`, only `INDETERMINATE`.

---

### Question 6: TSA time versus `signingTime`
> *The TSA says 10:42 and `signingTime` says 11:42. Which one wins, and why might they differ by one hour, or by three years?*

The **TSA time (`genTime`)** always wins:
- `signingTime` is written by the signer's computer using its local clock, which the signer fully controls (it may be misconfigured or deliberately altered).
- A difference of **one hour** (e.g. `10:42 UTC` versus `11:42`) usually comes from a time-zone mix-up (CET `UTC+1` in winter in Spain) or daylight saving time (CEST) on a poorly synchronised clock.
- A difference of **three years** can come from a dead CMOS battery, a misadjusted system clock, or a deliberate attempt to backdate or postdate the signing claim. So `notary verify` evaluates certificate validity exclusively at the TSA time (or `--at`) and shows `signingTime` only as the date claimed by the signer.

---

### Question 7: a certificate revoked today versus a signature from last month
> *A certificate is revoked today. Was a signature made last month valid? What information would you need to answer, and does OCSP give it to you?*

To decide whether a signature made last month was valid when the certificate shows as revoked today, we need to know:
1. **When the signature was really made:** proven by the timestamp (`genTime`) of a trusted TSA.
2. **When the revocation happened (`revocationTime`) and why (`revocationReason`):** that is, whether the revocation came after the timestamp and whether the key was already compromised before.

Does OCSP (RFC 6960) provide this?
- When the status in an OCSP `SingleResponse` is `revoked`, the `RevokedInfo` structure mandatorily includes **`revocationTime`** (and optionally `revocationReason`).
- If `revocationTime` is **earlier than or equal to** the TSA time, the signature is definitely **`INVALID`**, because the certificate was already revoked when it was stamped.
- However, an OCSP query made today has limits when validating historical signatures:
  1. If the certificate expired long ago, many OCSP responders stop maintaining its status or answer `unknown`.
  2. `revocationTime` reflects when the revocation was reported/recorded at the CA; if the holder lost the card days before reporting it, the key could have been used in between.
  3. If `revocationTime` is **later than** the evaluation time (TSA or `--at`), `notary verify` keeps the signature valid: the signature already existed, stamped, before the revocation. Without a timestamp the evaluation time is the current time, so any already recorded revocation invalidates the proof.
  4. That is why long-term profiles (CAdES-LT / CAdES-LTA) embed the OCSP response obtained at signing time (or shortly after the TSA stamp) in the signature itself, so it can be verified years later without depending on the OCSP server's current state.

---

### Question 8: what does a timestamp prove, and what does it not?
> *What does your timestamp prove about the moment of signing? Could the signature have been made earlier? Could someone else have made it with your card?*

#### What a CAdES-T signature proves
An RFC 3161 timestamp issued at $T_{\text{TSA}}$ over `SHA-256(signatureValue)` establishes an **upper time bound (*no later than $T_{\text{TSA}}$*)**:
1. **Prior existence of the document and the signature:** it proves mathematically that both the document (`messageDigest`) and the signature made with the private key tied to the certificate (`signingCertificateV2`) existed before $T_{\text{TSA}}$. Nobody, not even the private-key holder, can create a signature today and get an honest TSA to stamp it with last month's date.
2. **Causal order between creation, signing and stamping:** in every CAdES-T proof:
   $$T_{\text{document creation}} \;\le\; T_{\text{card signature}} \;\le\; T_{\text{TSA}}$$
   In `notary sign` the TSA request is sent immediately after the card produces `signatureValue`, with a fresh 64-bit `nonce`, so $T_{\text{signature}}$ and $T_{\text{TSA}}$ are normally only seconds apart.

#### What a timestamp does NOT prove
1. **It sets no lower bound (*how long before it was signed*):** the RFC 3161 stamp over `signatureValue` proves the signature was not made *after* $T_{\text{TSA}}$, but **the signature may have been computed hours, days or months before** being sent to the TSA. A signer could sign in January, keep the `.csig` private, and request the stamp in March; the stamp only proves the signature already existed in March, not that it was made in March. (To also bound the lower limit, something unpredictable and recent, such as a block or a previous stamp, would have to be included in the signed data before signing.)
2. **It does not prove who physically pressed the keys, nor the absence of coercion:** a DNIe signature proves the physical DNIe chip took part and its correct PIN was entered. By itself it does not prove the holder did not lend the card and PIN to someone else, that malware did not alter the bytes shown on screen before the hash was sent to the reader (*what you see is not what you sign*), or that the holder signed freely and without coercion.

---

## 3. Verifier decision rules (`notary verify`)

`notary verify` runs the 8 steps in order and returns one of three verdicts, never raising unhandled exceptions:

| Verdict | Exit code | Conditions |
| :--- | :---: | :--- |
| **`VALID`** | `0` | 1. The `.csig` is a valid CMS `SignedData` (`detached` or `attached`).<br>2. `messageDigest` matches the document hash.<br>3. `signingCertificateV2` (or `signingCertificate`) matches the signer certificate.<br>4. The mathematical signature over the `SET OF` (`0x31`) of `signedAttrs` is valid.<br>5. The signer chain is cryptographically valid up to a `--trust` anchor.<br>6. If there is a `signatureTimeStampToken`, its `messageImprint` is `Hash(signatureValue)`, its CMS signature and `ExtendedKeyUsage = timeStamping` are valid, and the TSA chain reaches a `--trust` anchor. (With no stamp, it explicitly warns that the only time is a claim.)<br>7. All certificates were valid at the TSA time (or `--at`).<br>8. The OCSP status is `GOOD` (or the certificate declares no OCSP URL in its AIA). |
| **`INVALID`** | `1` | Empty, truncated or corrupt file; `--content` missing for a `detached` signature; document modified (different `messageDigest`); `signingCertificateV2` mismatch; invalid RSA/ECDSA signature; a chain issuer is not a CA or its signature fails; the TSA stamp covers the document instead of the signature, or belongs to another signature; a certificate was expired or not yet valid at the evaluation time; or OCSP returns `REVOKED` (or an invalid OCSP signature). |
| **`INDETERMINATE`** | `2` | Signature and hashes are intact, but external information is missing to confirm trust or validity: no `--trust` was given, the signer or TSA chain does not link to any `--trust` certificate, the OCSP server is unreachable or answers `UNKNOWN`. |

---

### Robustness against malformed files

`notary verify` never ends with an exception: `asn1crypto` parses lazily, so a corrupt file can fail at any point of verification, not just on load. `run_verify` wraps the whole process and turns any unexpected exception into `INVALID` with the reason. A test that mutates random bytes (*fuzzing*) requires a verdict every time. Changes to the informational `digestAlgorithms` list of the CMS container do not alter the verdict, because the verifier uses the `SignerInfo` algorithm, which is signed.

### PAdES: signing inside a PDF

- **Structure.** `sign --format pades` does not rewrite the PDF: it appends an *incremental update* with (1) the signature dictionary (`/Type /Sig`, `/Filter /Adobe.PPKLite`, `/SubFilter /ETSI.CAdES.detached`, `/ByteRange`, `/Contents`, `/M`), (2) an invisible signature field (`/FT /Sig`, widget with `/Rect [0 0 0 0]`), (3) the modified catalog and page (`/AcroForm`, `/Annots`) and (4) a new cross-reference table pointing to the previous one with `/Prev`. If the original PDF uses an *xref stream*, the new section does too (a classic-table PDF gets a classic table). Earlier signatures keep verifying because their bytes do not change.
- **What the card signs.** The `/Contents` value is reserved with zeros (20,000 bytes) and `/ByteRange [0 a b c]` is filled with the real positions after the file is built. The CMS is the usual CAdES detached, computed over the PDF bytes outside the gap, with the RFC 3161 stamp over the signature value. The CMS has **no `signingTime`**: in PAdES the claimed date is `/M` (ETSI EN 319 142-1). If the CMS does not fit in the reserved space, `sign` fails instead of truncating it.
- **Verification.** `verify` detects the PDF by its header, locates each `/ByteRange` and requires: that it starts at 0; that the gap is exactly the hexadecimal value following `/Contents` (so the range cannot be pointed elsewhere, a *signature wrapping* attack); and that, after the **last** signature, no byte is left uncovered. An intermediate signature may stop short of the end of the file only because a later one covers it. It then applies to each signature the same steps as for a `.csig` (digest, signature, chain, stamp, validity, OCSP). `adbe.pkcs7.detached` (what Acrobat produces by default) is also accepted, without `signingCertificateV2`, warning that this link cannot then be checked.
- **Decision: bytes appended after the signature = `INVALID`.** A full validator (e.g. pyHanko) distinguishes which later changes are allowed (form filling, new signatures) according to the document permissions (DocMDP). Here they are not analysed, so any uncovered content is rejected: a conservative stance, at the cost of rejecting PDFs that another validator would accept for their original revision.
- **Independent cross-check.** A PDF signed with `notary` was validated with pyHanko (outside the program, only as a check): intact, valid and trusted signature covering the whole file, for classic PDFs, xref-stream PDFs, PDFs with catalog and pages inside object streams, and with a double signature. In the opposite direction, `notary verify` accepts a PAdES signed by pyHanko. Both detect one changed byte in the content.
- **Library.** `pypdf` is used only to *read* the catalog, page and trailer (a library for PDF structure, not for signing). Writing the incremental update, the `/ByteRange`, the signature, the stamp and the verification is our own code.

### PIN protection: the attempt counter cannot be queried

- **Problem.** The DNIe allows 3 consecutive wrong PINs before locking, and the last one must not be wasted. The obvious check is the PKCS#11 flag `CKF_USER_PIN_FINAL_TRY`, but **with this DNIe it is unreliable**: OpenSC 0.27.1 (`card-dnie.c`) does not support the PIN status query (`SC_PIN_CMD_GET_INFO` returns `NOT_SUPPORTED`) and the card only reports remaining attempts (`SW 63Cx`) in response to a **wrong** PIN. So in a new session the flag shows inactive even if attempts have been spent. This was observed with a real card: after two wrong PINs, `notary info` still showed `USER_PIN_FINAL_TRY` inactive.
- **Why the card is not asked.** A `VERIFY` with no data is the standard ISO 7816-4 query, but the DNIe requires an encrypted secure channel (CWA) for any command; improvising one against a card with few attempts left would be worse than the problem.
- **Solution: a local counter (`notary/pin_guard.py`).** `PKCS11Signer` records every `CKR_PIN_INCORRECT` and, after 2 failures in a row, refuses to ask for the PIN (leaving one attempt of margin). A correct PIN resets the count; `CKR_PIN_LOCKED` sets it to 3. Only the number of failures is stored per card, identified by a hash of its serial number, **never the PIN**. If the state file cannot be read, it refuses instead of assuming 0. The `notary pin-guard` command shows the counter and lets you set it (`--set N`) or reset it (`--reset`) without asking for the PIN.
- **Limitation.** It only counts attempts made with `notary`: those from AutoFirma, a browser or other programs are invisible to it, and if the PIN is changed at a PIN unlock kiosk it must be reset by hand. It is a safety net, not a guarantee.

### Embedded evidence (LTV) and multiple signatures

- **Embedded OCSP response:** if the signature carries a timestamp and an OCSP response for the signer certificate, `verify` uses it **offline**. It is validated like a live response (signature by the issuer or by a delegated responder with EKU `OCSPSigning`, `CertID`, status) and must also have been **produced after the timestamp**: an earlier response only says the certificate was fine *before* and does not rule out a revocation in between, so the verdict is `INDETERMINATE`. An embedded response saying `revoked` with `revocationTime` before the evaluation time gives `INVALID`. Without embedded evidence, `verify` queries OCSP live as before. The certificates in `certificateValues` help complete the chain; trust still comes only from `--trust`.
- **Freshness of the live response:** the request carries a random 16-byte nonce; if the response has a different nonce it is `INVALID`, and if it has none it is accepted (many responders do not support it; it is unknown whether the DNIe's does). The current time must also fall within `thisUpdate`–`nextUpdate` (5-minute margin); an expired or future response is `INDETERMINATE`. Without `nextUpdate`, it must be under 24 hours old.
- **Multiple signatures:** if the file has more than one `SignerInfo`, `verify` checks them one by one and shows each breakdown. The final verdict is the worst of all (`INVALID` > `INDETERMINATE` > `VALID`), so a single bad signature invalidates the set. The display order is set by the DER encoding (`SET OF` is sorted by bytes), not by signing order.
- **Issuing CAs:** besides `BasicConstraints CA=TRUE`, if the certificate declares `KeyUsage` it must include `keyCertSign`.

## 4. Known limitations

1. **CAdES-LT, not CAdES-LTA:** with `--ltv` the signer's chain and OCSP response are embedded, but not the TSA's (its chain already travels in the token with `certReq`), and no archive timestamps (`archiveTimeStamp`) are added. If the TSA certificate expires without re-stamping, the proof can no longer be verified in the future; CAdES-LTA would be needed.
2. **Nested countersignatures:** `cosign` adds parallel signatures, not countersignatures (`countersignature`).
3. **Basic PAdES:** the signature is invisible (no appearance on the page); there is no PAdES-LT/LTA (the `/DSS` dictionary with chain and OCSP is not written, which is why `--format pades` does not accept `--ltv`); encrypted PDFs are not supported; the signature is placed on the first page; DocMDP permissions are not analysed, so any modification after the last signature is rejected.
4. **OCSP nonce not mandatory:** if the server does not return the nonce, replay protection is reduced to the `thisUpdate`/`nextUpdate` window.
5. **DNIe Remote cannot sign:** the phone as a reader (`DNIeRemotePKCS11.dll`) reads the certificates, but signing fails at the PIN step. It was tried on two machines. On the first the program hung in `C_Login` until stopped with Ctrl+C. On the second (3 Nov 2026, DNIe paired over USB) `C_Login` returned `Unknown error (0x000000E9)`, which is not a standard PKCS#11 code, and the phone app showed "the operation cannot be successfully finished". There `PROTECTED_AUTHENTICATION_PATH` showed inactive, so `notary` asked for the PIN on the console. We do not know whether the PIN reached the card or why the module fails. With the USB reader and OpenSC everything works. `PKCS11Signer` now honours `CKF_PROTECTED_AUTHENTICATION_PATH` (calls `C_Login` with NULL and does not ask for the PIN on the console) and counts an interrupted `login` (Ctrl+C) as a spent attempt, but we do not know if that was the cause of the hang. The PIN counter only counts `CKR_PIN_INCORRECT`, and we do not know what code this module returns for a wrong PIN, so with the phone it may count fewer attempts than were spent. With a single module installed, `find_pkcs11_module` returns it without probing it (loading the module twice breaks DNIe Remote's communication), so the absence of a card is detected later, when listing slots.
6. **Signer OCSP status check:** the signer certificate is queried over OCSP, taking the URL from its AIA extension (`AuthorityInformationAccess`); for the trust roots (`--trust`) trust is direct, by user configuration.
