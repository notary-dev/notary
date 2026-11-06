# notary

Programa de línea de comandos que inspecciona el DNIe (`info`), firma documentos produciendo firmas estándar CAdES-T con sellos de tiempo RFC 3161 (`sign`) y verifica pruebas propias, de la pareja o de herramientas oficiales como AutoFirma (`verify`).

> **Estado:** Los tres comandos (`info`, `sign` con DNIe o firmante software, y `verify` con validación de cadenas X.509, sello RFC 3161, evaluación temporal `--at` y consulta de revocación OCSP) están implementados, más los extras CAdES-LT (`--ltv`), varias firmas en paralelo (`cosign`) y PAdES (firma dentro de un PDF), y cubiertos por 143 pruebas unitarias.

> **Documentación:**
> - **Autores:** Nacho Pola · Martín Longares
> - **Documento de diseño y *"Qué demuestra un sello de tiempo"*:** [docs/DESIGN.md](docs/DESIGN.md)
> - **Probar con un DNIe real:** [docs/PRUEBAS_DNIE.md](docs/PRUEBAS_DNIE.md) es la guía paso a paso (preparación, cada comando con el resultado esperado, casos que deben fallar).

## Requisitos

- Python 3.12 o superior.
- OpenSC (módulo PKCS#11) y un lector de DNIe USB, o DNIe Remote (móvil con NFC).
- AutoFirma, para comprobar la interoperabilidad de los ficheros `.csig`.

| | Windows | macOS | Linux (Debian/Ubuntu) |
|---|---|---|---|
| Python | instalador de python.org (marcar *Add to PATH*) | `brew install python` | `apt install python3-venv` |
| OpenSC | `.msi` de las releases de OpenSC en GitHub | `brew install opensc` | `apt install opensc pcscd` |
| Módulo PKCS#11 | `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll` (o `C:\Windows\System32\DNIeRemotePKCS11.dll`) | `$(brew --prefix)/lib/pkcs11/opensc-pkcs11.so` | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |

Antes de firmar con la tarjeta conviene comprobar que el lector detecta el DNIe (ninguno de estos dos comandos solicita el PIN):

```
pkcs11-tool --list-slots
pkcs11-tool --list-objects --type cert
```

## Instalación

```
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS, Linux
pip install -e .
```

`pip install -e .` instala las dependencias (`PyKCS11`, `asn1crypto`, `cryptography`, `requests` y `pypdf`, esta última solo para leer la estructura del PDF) y crea el ejecutable `notary`. También se puede invocar como `python -m notary ...` desde la raíz del repositorio.

## Uso

```
notary info   [--module RUTA]
notary sign   <fichero> [--format detached|attached|pades] [--tsa URL ...] [--out FICHERO] [--module RUTA] [--key CLAVE.pem --cert CERT.pem] [--no-timestamp]
notary verify <prueba.csig> [--content FICHERO] [--trust FICHERO ...] [--at TIEMPO]
notary cosign <prueba.csig> <fichero> [--tsa URL ...] [--out FICHERO] [--module RUTA] [--key CLAVE.pem --cert CERT.pem] [--ltv [--chain CERT ...]]
```
`sign` y `cosign` aceptan además `--ltv [--chain CERT ...]` (ver abajo).

### 1. Diagnóstico del DNIe (`notary info`)
- Lista los lectores y ranuras PKCS#11, muestra los flags de seguridad del PIN (`USER_PIN_FINAL_TRY`, `USER_PIN_LOCKED`, etc.) y lee los certificados públicos de la tarjeta en una sesión sin login (**nunca pide el PIN**).
- Identifica `CertFirmaDigital` (`content_commitment` / `non_repudiation`) y `CertAutenticacion` (`digital_signature`) a partir de la extensión `KeyUsage`.

### 2. Firma CAdES-T (`notary sign`)
- **Con el DNIe (por defecto):** selecciona automáticamente `CertFirmaDigital`, comprueba antes de pedir el PIN que `CKF_USER_PIN_FINAL_TRY` y `CKF_USER_PIN_LOCKED` no estén activos, solicita el PIN con `getpass` (sin eco y sin reintentos automáticos) y pide al chip que firme el bloque `DigestInfo` SHA-256 de los atributos firmados (`SET OF`, `0x31`).
- **Con el firmante software de desarrollo (`--key` y `--cert`):** permite desarrollar y ejecutar pruebas sin usar la tarjeta física.
- **Sello de tiempo RFC 3161:** se solicita sobre `SHA-256(signatureValue)` con un `nonce` aleatorio de 64 bits y `certReq=True`, probando por orden ACCV (`tss.accv.es`), `freetsa.org`, DigiCert, Sectigo, GlobalSign y Certum (o las URLs de `--tsa`). Si ninguna TSA responde, `sign` falla y **no escribe ninguna firma sin sello**.
- **`--no-timestamp` (solo desarrollo):** produce CAdES-BES sin sello e imprime un aviso indicando que `signingTime` es solo una declaración del firmante.

Ejemplos:
```
# Firmar con el DNIe (CAdES-T detached)
notary sign documento.pdf

# Firmar con credenciales de prueba locales (CAdES-T attached)
notary sign documento.pdf --format attached --key tools/test_certs/signer.key --cert tools/test_certs/signer.crt
```

### 2 pre. Protección del PIN (`notary pin-guard`)
El DNIe se bloquea tras 3 PIN incorrectos seguidos y, con OpenSC, **no se puede consultar cuántos quedan** (el flag `USER_PIN_FINAL_TRY` no es fiable). Por eso `notary` cuenta los fallos por su cuenta y, tras 2 seguidos, **se niega a pedir el PIN**. Solo guarda un contador por tarjeta, nunca el PIN.
```
notary pin-guard              # muestra el contador
notary pin-guard --set 2      # fija el contador si sabes cuántos intentos se han gastado
notary pin-guard --reset      # lo reinicia (tras un PIN correcto fuera de notary o tras pasar por un PAD)
```
Solo cuenta los intentos hechos con `notary`; si dudas del PIN, compruébalo en un Punto de Actualización del DNIe en vez de probar.

### 2 bis. Extras: validación a largo plazo (`--ltv`) y varias firmas (`cosign`)
- **`notary sign doc.pdf --ltv`** (CAdES-LT): tras el sello de tiempo, incrusta en la firma la cadena de certificados del firmante y una respuesta OCSP. La cadena se descarga de la AIA del certificado (`caIssuers`); con `--chain CERT ...` se pueden dar los emisores a mano (necesario con la CA de pruebas). Si no se puede reunir la evidencia, `sign` falla y no escribe nada. `verify` usa esa respuesta **sin red**, siempre que se produjera después del sello de tiempo.
- **`notary cosign prueba.csig doc.pdf`**: añade una segunda firma en paralelo (otro DNIe o el firmante software) con su propio sello, sin tocar la original (por defecto escribe `prueba.multi.csig`). `verify` muestra cada firmante y el veredicto final es el peor de todos.

### 2 ter. PAdES: firmar dentro de un PDF (`--format pades`)
```
notary sign contrato.pdf --format pades        # escribe contrato.signed.pdf
notary verify contrato.signed.pdf --trust ACRaiz2.crt AC006.crt <raíz de la TSA>
```
- La firma se añade como **actualización incremental**: los bytes del PDF original no se tocan y se anexan una firma, un campo de firma invisible y una nueva tabla de referencias. La firma (`/SubFilter /ETSI.CAdES.detached`) cubre todo el archivo menos el valor `/Contents` (`/ByteRange`) y lleva sello de tiempo (PAdES-B-T).
- Para añadir **otro firmante** basta con volver a firmar el PDF ya firmado; las firmas anteriores siguen válidas. `verify` muestra cada firma y el veredicto final es el peor de todos.
- Funciona con PDF clásicos y con los modernos (referencias en *xref stream* y objetos en *object streams*). No admite PDF cifrados.
- `--format pades` no se combina con `--ltv` ni con `cosign`. La firma es invisible: un lector de PDF la muestra en su panel de firmas, no sobre la página.

### 3. Verificación (`notary verify`)
Verifica paso a paso un archivo `.csig` (`detached` o `attached`, propio, de la pareja o de AutoFirma) o un PDF firmado (PAdES; si el archivo empieza por `%PDF-`, se verifican todas sus firmas) y emite `VEREDICTO: VALID` (código `0`), `VEREDICTO: INVALID` (código `1`) o `VEREDICTO: INDETERMINATE` (código `2`):
1. Estructura CMS `SignedData` y coherencia del modo `detached`/`attached` con `--content`.
2. Resumen del documento frente a `messageDigest`.
3. Certificado del firmante y correspondencia con `signingCertificateV2` (o `signingCertificate`).
4. Firma matemática RSA/ECDSA sobre `signedAttrs` codificado como `SET OF` (`0x31`).
5. Cadena de certificación X.509 hasta un ancla configurada en `--trust`.
6. Token de sello de tiempo RFC 3161 (`messageImprint == Hash(signatureValue)`, firma CMS de la TSA, `ExtendedKeyUsage = timeStamping` y cadena de la TSA hasta `--trust`). Si el fichero no lleva sello, advierte que la única hora es una declaración.
7. Vigencia temporal de los certificados en la hora de la TSA (o en el instante ISO 8601 indicado con `--at`).
8. Estado de revocación por **OCSP**, extrayendo dinámicamente la URL de la extensión AIA (`AuthorityInformationAccess`) del certificado. La petición lleva un nonce y la respuesta debe estar vigente (`thisUpdate`–`nextUpdate`). Si la firma lleva una respuesta OCSP incrustada (`--ltv`), se usa esa, sin red.

Ejemplo:
```
notary verify documento.pdf.csig --content documento.pdf --trust ACRaiz2.crt AC006.crt freetsa_root.crt
```

## Herramientas auxiliares (`tools/`)

- **Generar CA y certificados de prueba (incluyendo certificado de corta duración):**
  ```
  python -m tools.generate_test_ca
  ```
- **Generar el lote de 6 pruebas (2 válidas y 4 defectuosas) y su Answer Key para el *Pair Exchange*:**
  ```
  # A partir de una firma real hecha con el DNIe:
  python -m tools.forger --base-proof doc.pdf.csig --base-content doc.pdf --output-dir pair_exchange

  # O en modo autónomo de prueba sin tarjeta ni red:
  python -m tools.forger --self-test --output-dir pair_exchange_test
  ```

## Pruebas automatizadas

```
python -m unittest discover -s tests -t . -v
```

Las 143 pruebas cubren el constructor CAdES, el cliente TSA, la CLI, la detección PKCS#11, `PKCS11Signer`, el verificador completo (cadenas, sello TSA, expiración en hora TSA / `--at`, OCSP con nonce y frescura, evidencia LTV, varias firmas, PAdES, robustez ante archivos corruptos) y el generador `forger.py`, sin necesitar DNIe conectado ni red.

## Comprobar una firma con OpenSSL (a mano)

```
openssl cms -verify -binary -inform DER -in doc.csig -content doc -CAfile tools/test_certs/test_ca.crt
```

`-binary` es necesario para firmas `detached`: sin él, algunas compilaciones de OpenSSL en Windows tratan el documento como texto y fallan aunque la firma sea correcta.

## Privacidad

Las firmas hechas con el DNIe contienen tu nombre completo y tu número de DNI. No subas a git firmas reales; para los tests usa la CA de pruebas (`tools/generate_test_ca.py`).
