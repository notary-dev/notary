# Testing `notary` with a real DNIe

Steps to test **the whole program** with a real DNIe, cleanly and in order. Written for someone starting from scratch with their own card. A results table is at the end.

> **What is tested:** `info`, CAdES-T signing (detached and attached), `verify` against the real TSAs and the DNIe OCSP, interoperability with OpenSSL / AutoFirma / VALIDe, cases that must fail, CAdES-LT (`--ltv`), PAdES (PDF), multiple signatures (`cosign`).
>
> Program output quoted below (`VEREDICTO`, `Introduce el PIN del DNIe`, ...) is in Spanish, as the tool prints it.

---

## 0. PIN rules (read before starting)

The DNIe locks after **3 consecutive wrong PINs**, and can only be unlocked at an official DNIe update kiosk (PAD), with your fingerprint. With this DNIe the remaining attempts cannot be queried.

1. **If a PIN fails, do not retry.** Stop and check the PIN at a PAD.
2. `notary` counts failures and, after **2 in a row**, refuses to ask for the PIN. That is the protection working, not an error.
3. Only you type the PIN, in your own terminal, when `notary` asks (it is not echoed). Do not paste it in any chat, file or command.
4. If you doubt the PIN, do not try "maybe it's this one": go to the PAD.
5. Close AutoFirma, Firefox and any program that may hold the card open before testing.

If you already failed an attempt outside `notary` (AutoFirma, a browser...), tell the program: `notary pin-guard --set N` (N = failed attempts used).

---

## 1. Setup (once)

### 1.1 Code and environment

```powershell
cd <repository-folder>
git pull
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # if PowerShell blocks it: use  .\.venv\Scripts\python.exe -m notary ...  instead of  notary ...
pip install -e .
python -m unittest discover -s tests   # must end in OK (143 tests), without touching the card
```

### 1.2 OpenSC and reader

```powershell
winget install --id OpenSC.OpenSC --source winget
```

Plug in the reader and place the DNIe **chip up, touching the reader**. If it does not respond, reposition it and clean the contacts. Check without PIN:

```powershell
& "C:\Program Files\OpenSC Project\OpenSC\tools\opensc-tool.exe" -n      # must print:  dnie
```

### 1.3 Working folder and trust certificates

**Outside the repository**: signatures made with your DNIe contain your name and ID number and must not end up in git. The folder looks like this: `firmas_propias\` (your signatures and documents), `trust\` and `evidencia\`.

```powershell
$W = "$HOME\notary-dnie"; $MIS = "$W\firmas_propias"   # $MIS: your signatures and documents
New-Item -ItemType Directory -Force "$W\trust","$MIS" | Out-Null
"Test document for notary." | Set-Content "$MIS\doc.txt"

# DNIe root and intermediate CAs (PEM). Any of AC DNIE 004/005/006 works; download all.
foreach ($f in "ACRaiz2","AC004","AC005","AC006") {
  Invoke-WebRequest "http://pki.policia.es/dnie/certs/$f.crt" -OutFile "$W\trust\$f.crt" }
# FreeTSA root and public roots (DigiCert, Sectigo) to verify the timestamps
Invoke-WebRequest "https://freetsa.org/files/cacert.pem" -OutFile "$W\trust\freetsa_root.pem"
Copy-Item (python -c "import certifi; print(certifi.where())") "$W\trust\raices_publicas.pem"
```

> If `notary info` shows an issuing CA other than AC DNIE 004/005/006, download its certificate from `http://pki.policia.es/dnie/certs/` into the same folder.

To shorten the verification commands:

```powershell
$T = Get-ChildItem "$W\trust" | ForEach-Object FullName     # all trust certificates
```

### 1.4 Network: cable (Ethernet) or Wi-Fi

Everything except DNIe Remote works the same over cable or Wi-Fi. You only need outbound access on ports 80 and 443 to the TSAs, the DNIe OCSP and the police PKI. Check before starting:

```powershell
foreach ($d in @(@("freetsa.org",443), @("timestamp.digicert.com",80), @("timestamp.sectigo.com",80), @("ocsp.dnie.es",80), @("pki.policia.es",80))) {
  $ok = Test-NetConnection -ComputerName $d[0] -Port $d[1] -InformationLevel Quiet -WarningAction SilentlyContinue
  "{0,-26} port {1,-4} {2}" -f $d[0], $d[1], $(if ($ok) { "OK" } else { "FAIL" })
}
```

**Expected:** `OK` on all five lines. If one fails, that network blocks the port, common on university or company networks. Try another network, for example a phone hotspot. If only FreeTSA fails it is not serious: `notary` moves on to the next TSA (step 6). If `ocsp.dnie.es` fails, `verify` gives `INDETERMINATE`.

To see which adapter you reach the Internet through:

```powershell
Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, LinkSpeed | Format-Table -AutoSize
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize
```

A PC may show several adapters at once. `vEthernet` (Hyper-V, WSL), Docker and VPN adapters are virtual. The one that counts is your cable or Wi-Fi adapter, carrying your router's subnet IP (usually `192.168.x.x`).

### 1.5 Alternative: the phone as a reader (DNIe Remote)

Without a USB reader, an NFC phone can act as the reader with the police's **DNIeRemote** application (a Windows part and an Android part). **In this project it did not work** for signing: it was tried on two machines. It reads the certificates (`notary info` shows them), but the PIN step fails: on one machine it hung, on the other `C_Login` returned `Unknown error (0x000000E9)` and the phone app said "the operation cannot be successfully finished". If you try it, do so only to check, with a single attempt. For signing, use the USB reader with OpenSC.

Installation: the DNIe Remote installer (`Instalador_DNIeRemote_x64.exe`) refuses to install ("a newer version is already installed") if the card-reader "Instalable DNIe" is present. Uninstall that first. Afterwards `C:\Windows\System32\DNIeRemotePKCS11.dll` and the `DNIeRemoteSvc` service exist. The phone app is called DNIeSmartConnect, not MiDNI. What the [official manual](https://www.dnielectronico.es/PDFs/DNIeRemote_user_manual.pdf) (v1.3.28, 2020) does say:

- PC and phone pair over **USB** (with USB debugging enabled and MTP file transfer) or over **Wi-Fi** (the phone scans the QR code the Windows wizard shows).
- **USB does not use the network**, so it works the same with the PC on cable, on Wi-Fi or offline. It is the first option if Wi-Fi pairing gives trouble.
- With Wi-Fi, PC and phone must be **on the same network**. Both having Internet is not enough. If the QR gives "La información recuperada no es válida", the manual says the cause is that they are not.
- Communication goes over a secure channel and the manual says it does not matter whether the network is public or private. Still, if Wi-Fi pairing takes more than 10 seconds, the manual points to the **Windows firewall** and asks you to check that a rule exists for DNIeRemote.
- The PKCS#11 module is `DNIeRemotePKCS11.dll`, in `C:\Windows\System32\`. If it is the only module installed, `notary` uses it automatically. If you also have OpenSC, say so: `--module "C:\Windows\System32\DNIeRemotePKCS11.dll"`.
- **It is not 100 % compatible with AutoFirma.** The manual says you can only sign directly from the Mozilla Firefox store, and that AutoFirma needs the `-store mozilla` command-line option. This affects only *signing with AutoFirma*. To **verify** in AutoFirma or VALIDe no reader is needed.

**If `notary sign` hangs at "Conectando con el DNIe y verificando PIN...".** This happened with the PC on cable and the phone on Wi-Fi, same network. The program managed to read the certificates through the phone, so pairing and network worked, and the module's `C_Login` call did not return until stopped with Ctrl+C. So the problem is in the PIN step, not in the network. Before cutting, look for:

- A DNIe Remote **window** asking for the PIN, perhaps behind others, or a **request on the phone**.
- What `notary info` says for `PROTECTED_AUTHENTICATION_PATH`. If it is `ACTIVO`, the module expects the PIN outside the terminal and `notary` no longer asks for it on the console: it passes control to the module as the PKCS#11 standard requires and tells you to type it in the window, the reader keypad or the phone. **We could not test this with DNIe Remote.**
- If you cut with Ctrl+C during that step, `notary` **counts it as a PIN attempt**, because it does not know whether the PIN reached the card. If you cut with an earlier version of the program, that attempt was not counted: adjust the counter with `notary pin-guard --set N` and, if in doubt, check the PIN at a PAD before continuing.

For **pairing** problems, the manual ties each message to a cause:

- "La información recuperada no es válida" when scanning the QR points to PC and phone not being on the same network.
- Wi-Fi pairing taking more than 10 seconds points to the Windows firewall.
- "Error de comunicación. Se ha perdido la conexión con el DNIe" when bringing the DNI to the phone points to NFC. The manual says it is very fragile, very short range, and the DNI must sit right over the phone's antenna without moving.

**To separate the network from everything else, pair over USB**, which does not use the network. If the network is the suspect, check that the router does not isolate clients or use a guest network, and compare the PC's IPv4 with the phone's (Settings, Wi-Fi, your network). With a `/24` mask, the usual one, the first three numbers match (for example `192.168.1.x`).

**PC with virtual adapters.** *This is our hypothesis and is not in the manual.* If DNIeRemote advertised the IP of a virtual adapter (Hyper-V, WSL, VPN), the phone could not reach the PC. If pairing fails and your PC has several adapters, disable the virtual ones and VPNs while pairing, or use USB.

**Firewall.** To see whether the DNIeRemote rule exists and which network type it applies to, and which type of network you have:

```powershell
Get-NetFirewallApplicationFilter | Where-Object { $_.Program -like '*DNIeRemote*' } | Get-NetFirewallRule | Format-Table DisplayName, Enabled, Direction, Action, Profile -AutoSize
Get-NetConnectionProfile | Format-Table Name, InterfaceAlias, NetworkCategory -AutoSize
```

If the rule only covers the `Private` profile and your network is `Public`, the firewall blocks the connection. You have three ways out: pair over USB, switch that network to Private (relaxes the firewall for that network) or widen the rule's profile. That decision is yours, which is why `notary` does not take it for you.

To check or start the Windows services (`SCardSvr` and `DNIeRemoteSvc`) as administrator, run `Start-Service SCardSvr, DNIeRemoteSvc` and query `Get-Service SCardSvr, DNIeRemoteSvc`. The official manual does not mention any service called `DNIeRemoteSvc`, although the DNIe Remote installer registers it in Windows.

With the phone, `notary`'s PIN counter may fall short. It only counts the `CKR_PIN_INCORRECT` error, and we do not know what code DNIe Remote returns for a wrong PIN. If an attempt fails with another error, check `notary pin-guard` and treat it as a spent attempt.

---

## 2. Recognise the card (no PIN)

```powershell
notary info
notary pin-guard
```

**Expected:** a "DNI electrónico" token, the `CertAutenticacion` (usage `digital_signature`) and `CertFirmaDigital` (usage `non_repudiation`) certificates with their issuer (`AC DNIE 00X`) and validity, and `USER_PIN_LOCKED` / `USER_PIN_FINAL_TRY` inactive. `pin-guard` must say `0 de 3`.

> **Check the certificates are not expired.** If they are, renew them at a PAD before continuing.

---

## 3. Basic CAdES-T signature with the DNIe

```powershell
notary sign "$MIS\doc.txt"
```

It asks `Introduce el PIN del DNIe:` (once). An OpenSC window asking you to confirm the signature may open: accept it. It signs on the card, requests the timestamp from FreeTSA and writes `doc.txt.csig`.

**Expected:** steps `[1]` to `[6]`, `sellado por https://freetsa.org/tsr`, `Resultado ... CAdES-T` and `Escrito ... doc.txt.csig`.

## 4. Verify your own signature

```powershell
notary verify "$MIS\doc.txt.csig" --content "$MIS\doc.txt" --trust $T
```

**Expected:** `VEREDICTO: VALID — firmado por <your name> (FIRMA), no más tarde de <UTC time>`, with:

- `[4]` RSA PKCS#1 v1.5 / SHA256 signature;
- `[5]` chain `... (FIRMA) -> AC DNIE 00X -> AC RAIZ DNIE 2`;
- `[6]` the FreeTSA stamp and its chain;
- `[8]` OCSP `GOOD (http://ocsp.dnie.es)`.

> The DNIe OCSP answers over HTTP (not HTTPS) and returns the nonce; the response is valid for one hour.

## 5. Attached signature

```powershell
notary sign "$MIS\doc.txt" --format attached --out "$MIS\doc_attached.csig"
notary verify "$MIS\doc_attached.csig" --trust $T
```

No `--content`, because the document is inside. **Expected:** `VALID`.

## 6. Several TSAs: if the first fails, use the next

```powershell
notary sign "$MIS\doc.txt" --tsa http://tsa-que-no-existe.invalid https://freetsa.org/tsr --out "$MIS\doc_tsa2.csig"
```

**Expected:** `fallo (...)` for the first and `sellado por https://freetsa.org/tsr`. Optional: repeat with `http://timestamp.digicert.com` and `http://timestamp.sectigo.com`, and verify each (each TSA fills the token differently).

---

## 7. Interoperability with official tools

### 7.1 OpenSSL (by hand)

```powershell
openssl cms -verify -binary -inform DER -in "$MIS\doc.txt.csig" -content "$MIS\doc.txt" -noverify -out "$MIS\verificado.bin"
```

**Expected:** `CMS Verification successful`. (`-noverify` skips the chain; what is checked here is the signature.) Windows PowerShell 5.1 shows that message looking like a red error because OpenSSL writes it to the error stream; if it says `successful`, it worked. If your OpenSSL is not in the PATH, use Git's: `C:\Program Files\Git\usr\bin\openssl.exe`.

### 7.2 AutoFirma and VALIDe

- **AutoFirma:** *Verificar firma* → pick `doc.txt.csig` and, if asked, `doc.txt`. It must report a valid signature.
- **VALIDe** (`https://valide.redsara.es`): *Validar firma* → upload the signature and the document.
- Take a screenshot of each.

---

## 8. Cases that must fail

All on the same signature. None uses the card.

```powershell
# 8.1 Modified document  ->  INVALID (digest does not match)
"otro contenido" | Set-Content "$MIS\otro.txt"
notary verify "$MIS\doc.txt.csig" --content "$MIS\otro.txt" --trust $T

# 8.2 No trust certificates  ->  INDETERMINATE (the chain cannot be validated)
notary verify "$MIS\doc.txt.csig" --content "$MIS\doc.txt"

# 8.3 Evaluated before your certificate existed (set a date before its "Valid from")  ->  INVALID
notary verify "$MIS\doc.txt.csig" --content "$MIS\doc.txt" --trust $T --at 2020-01-01T00:00:00Z

# 8.4 Truncated file  ->  INVALID, no exceptions
$b = [IO.File]::ReadAllBytes("$MIS\doc.txt.csig"); [IO.File]::WriteAllBytes("$MIS\truncada.csig", $b[0..($b.Length-41)])
notary verify "$MIS\truncada.csig" --content "$MIS\doc.txt" --trust $T

# 8.5 Detached signature without giving the document  ->  INVALID (asks for --content)
notary verify "$MIS\doc.txt.csig" --trust $T
```

Exit codes: `0` = VALID, `1` = INVALID, `2` = INDETERMINATE (`$LASTEXITCODE`).

---

## 9. CAdES-LT: evidence inside the signature (`--ltv`)

```powershell
notary sign "$MIS\doc.txt" --ltv --out "$MIS\doc_ltv.csig"
```

It downloads the issuing CA from your certificate's AIA, requests an OCSP response and embeds both after the stamp. **Expected:** `Resultado ... CAdES-LT`. If it cannot gather the evidence (for example, no network), it fails with a `[!]` message and **writes no file**. This is the step that depends most on the real DNIe: if it fails, keep the full output.

Then, **disconnect all networks** and verify. If your PC has both cable and Wi-Fi, cut both: unplug the cable and turn off Wi-Fi (on a laptop, airplane mode does it all). Check you really are offline, because with a connection still active the test proves nothing:

```powershell
Test-NetConnection ocsp.dnie.es -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue     # must give False
notary verify "$MIS\doc_ltv.csig" --content "$MIS\doc.txt" --trust $T
```

With administrator rights you can also use `Disable-NetAdapter -Name "Wi-Fi" -Confirm:$false` and go back with `Enable-NetAdapter -Name "Wi-Fi"` (the adapter name comes from `Get-NetAdapter`).

**Expected:** `VALID` with `[8] ... GOOD (incrustada en la firma, LTV; verificada sin red)`. Reconnect when done.

> Control check: `doc.txt.csig` (without `--ltv`) verified **offline** must give `INDETERMINATE`, because it cannot query OCSP.

---

## 10. PAdES: signing inside a PDF

Use any PDF (`$MIS\ejemplo.pdf`).

```powershell
notary sign "$MIS\ejemplo.pdf" --format pades          # writes ejemplo.signed.pdf
notary verify "$MIS\ejemplo.signed.pdf" --trust $T
```

**Expected:** `[1] Formato ... PAdES (ETSI.CAdES.detached)` and `VALID`. Open `ejemplo.signed.pdf` in a PDF reader (Adobe Acrobat, AutoFirma or VALIDe) and look at the signatures panel. Take a screenshot.

> The signature is invisible (not drawn on the page): it shows in the reader's signatures panel. If Acrobat says the identity is not trusted, that is normal: it does not have the DNIe root installed.

Negative test: append text to the end of the signed PDF and verify; **expected** `INVALID` (`bytes añadidos después de la última firma`).

```powershell
Add-Content "$MIS\ejemplo.signed.pdf" "contenido anadido"
notary verify "$MIS\ejemplo.signed.pdf" --trust $T
```

---

## 11. Multiple signatures (`cosign`)

You need **two signers**: two people's DNIe (or, to test alone, the software signer). It checks that `verify` shows all of them.

```powershell
# Signer A signs as in step 3 (doc.txt.csig). Signer B adds their signature with THEIR DNIe and THEIR PIN:
notary cosign "$MIS\doc.txt.csig" "$MIS\doc.txt" --out "$MIS\doc_dos_firmas.csig"
notary verify "$MIS\doc_dos_firmas.csig" --content "$MIS\doc.txt" --trust $T
```

**Expected:** `=== Firmante 1 de 2 ===`, `=== Firmante 2 de 2 ===` and `VEREDICTO FINAL: VALID (2 firmantes; ...)`. The original signature is not modified.

For a PDF, just sign the already signed PDF again (step 10) with the other DNIe.

---

## Results table

| # | Test | Expected result | OK? | Notes |
| --- | --- | --- | --- | --- |
| 1.4 | Network diagnostic (cable or Wi-Fi) | `OK` on all five lines | ☐ | |
| 2 | `notary info` and `pin-guard` | card and valid certificates; `0 de 3` | ☐ | |
| 3 | `sign` detached | `CAdES-T`, stamped by FreeTSA | ☐ | |
| 4 | `verify` own signature | `VALID`, OCSP `GOOD` | ☐ | |
| 5 | `sign` + `verify` attached | `VALID` | ☐ | |
| 6 | TSA fallback | 1st fails, 2nd stamps | ☐ | |
| 7.1 | OpenSSL | `CMS Verification successful` | ☐ | |
| 7.2 | AutoFirma / VALIDe | valid signature (screenshot) | ☐ | |
| 8.1–8.5 | Negative cases | INVALID / INDETERMINATE as appropriate | ☐ | |
| 9 | `--ltv` and offline verification | `VALID`, "incrustada en la firma" | ☐ | |
| 10 | PAdES | `VALID` and visible in the reader (screenshot) | ☐ | |
| 11 | `cosign` | `VEREDICTO FINAL: VALID (2 firmantes)` | ☐ | |

---

## If something fails

| Symptom | What to do |
| --- | --- |
| `No se han encontrado módulos PKCS#11` | Install OpenSC (1.2), or DNIe Remote (1.5), or give the module with `--module "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"`. |
| `ninguno detecta un token presente`, `CKR_DEVICE_ERROR`, `Unresponsive card` | Reposition the DNIe chip up, clean the contacts and close AutoFirma/Firefox. Check with `opensc-tool -n` (must say `dnie`). |
| `notary se niega a pedir el PIN` / `Se han registrado N PIN incorrectos` | It is the protection. **Do not bypass it:** check the PIN at a PAD and then `notary pin-guard --reset`. |
| `CKR_PIN_INCORRECT` | **Stop.** Do not retry. Check the PIN at a PAD. |
| `INDETERMINATE ... no se encuentra el certificado emisor` | A CA is missing from `--trust`: add `AC DNIE 00X`, `ACRaiz2` or the TSA root. |
| `INDETERMINATE` because of OCSP | No network, or the server does not answer. Retry later. |
| The network diagnostic (1.4) shows `FAIL` on a port | That network blocks it (university, company, eduroam). Use another network, for example a phone hotspot. |
| DNIe Remote: "La información recuperada no es válida" when scanning the QR | The manual ties it to PC and phone not being on the same network (1.5). Compare their IPv4s, disable VPNs and virtual adapters, or pair over USB. |
| DNIe Remote: `sign` hangs at "verificando PIN" | Look for a window or a phone request waiting for the PIN, and what `PROTECTED_AUTHENTICATION_PATH` says in `notary info` (1.5). Ctrl+C counts as a PIN attempt. |
| DNIe Remote: Wi-Fi pairing takes more than 10 s | Probably the firewall (1.5): check the DNIeRemote rule and the network type, or pair over USB. |
| `respuesta OCSP caducada` | The computer clock is off. |
| `INVALID ... caducado` | The DNIe certificate has expired: renew it at a PAD. |
| The OpenSC confirmation window does not appear | Check whether it ended up behind another window; without accepting it nothing is signed. |

**If you need help,** copy the command's full output (not the PIN: it never appears in any output). Before pasting it in a chat or sending it, **cover your name and ID number**, which show up in `info` and `verify`.
