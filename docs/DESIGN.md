# Documento de Diseño — `notary`

**Autores:** Nacho Pola · Martín Longares

---

## 1. Arquitectura y Formatos

### 1.1 Estructura modular del programa
El paquete `notary` separa el acceso al hardware criptográfico, la construcción ASN.1/CMS, la comunicación en red (TSA y OCSP) y el motor de verificación:

- **Interfaz de firmante (`notary/signer/`):**
  - `Signer` (`base.py`): interfaz abstracta con `get_certificate() -> asn1crypto.x509.Certificate` y `sign_hash(digest: bytes) -> bytes`.
  - `SoftwareSigner` (`software_signer.py`): carga una clave privada RSA y un certificado PEM locales, comprueba que sus claves públicas coinciden y firma resúmenes SHA-256 de 32 bytes.
  - `PKCS11Signer` (`pkcs11_signer.py`): localiza el módulo PKCS#11, comprueba los flags de seguridad del PIN (`CKF_USER_PIN_LOCKED` y `CKF_USER_PIN_FINAL_TRY`), selecciona en sesión pública el certificado de firma (`CertFirmaDigital`), solicita el PIN con `getpass` sin reintentos automáticos y envía la estructura `DigestInfo` (51 bytes) a la tarjeta mediante `CKM_RSA_PKCS`.
- **Constructor CAdES (`notary/cades/builder.py`):**
  - Construye un contenedor CMS `ContentInfo` (`1.2.840.113549.1.7.2`, `signedData`) codificado en DER.
  - Soporta modo `detached` (`encapContentInfo.eContent = None`, el documento viaja aparte) y modo `attached` (`encapContentInfo.eContent = OctetString(content)`).
  - Incluye en `signedAttrs` los cuatro atributos obligatorios (`contentType`, `messageDigest`, `signingTime`, `signingCertificateV2`) y, en CAdES-T, añade el token RFC 3161 en `unsignedAttrs` (`signatureTimeStampToken`, OID `1.2.840.113549.1.9.16.2.14`).
- **Cliente TSA RFC 3161 (`notary/tsa.py`):**
  - Calcula `SHA-256(signatureValue)`, genera un `nonce` aleatorio criptográfico, solicita `certReq = True` y recorre las TSAs configuradas por orden hasta obtener una respuesta `granted` cuyo `messageImprint` y `nonce` coincidan.
- **Evidencia LTV y varias firmas (`notary/cades/ltv.py`, `notary/evidence.py`, `add_parallel_signature` en `builder.py`):**
  - `sign --ltv` añade, tras el sello de tiempo, dos atributos no firmados de ETSI EN 319 122-1: `certificateValues` (cadena del firmante, `1.2.840.113549.1.9.16.2.23`) y `revocationValues` con la respuesta OCSP (`...2.24`). El resultado es CAdES-LT. La cadena se toma de `--chain` o se descarga de la AIA (`caIssuers`) del certificado, y la respuesta OCSP se valida antes de incrustarla: si no se puede reunir la evidencia, `sign` falla y no escribe nada.
  - `cosign` añade un segundo `SignerInfo` en paralelo a un `.csig` existente: cada firmante firma el documento por su cuenta y lleva su propio sello. Las firmas anteriores se conservan byte a byte.
- **Verificador y cliente OCSP (`notary/verify.py`, `notary/ocsp.py`):**
  - Desmonta el `.csig`, valida la integridad del documento, los atributos firmados, la firma matemática, la cadena del firmante hasta `--trust`, el sello de tiempo RFC 3161 (imprint, firma CMS de la TSA, `ExtendedKeyUsage = timeStamping` y cadena de la TSA hasta `--trust`), la vigencia temporal en la hora de la TSA (o `--at`) y el estado de revocación por OCSP.

---

## 2. Respuestas a las Preguntas de Diseño (Sección 5.3 del Guion)

### Pregunta 1: Los dos certificados del DNIe
> *The DNIe has two certificates. Which one must sign a document, and how does your program tell them apart without relying on their labels?*

El DNIe contiene dos certificados de usuario final emitidos por la Dirección General de la Policía:
1. **`CertFirmaDigital`** (certificado de firma electrónica reconocida/cualificada): es el que debe usarse para firmar documentos.
2. **`CertAutenticacion`** (certificado de autenticación): destinado a autenticar al titular ante servidores o sesiones (por ejemplo, TLS cliente).

`notary` los distingue inspeccionando la extensión estándar X.509 **`KeyUsage`** (OID `2.5.29.15`, RFC 5280) del certificado:
- El certificado de firma declara el bit **`non_repudiation`** (denominado **`content_commitment`** en RFC 5280 y en `asn1crypto`/`cryptography`).
- El certificado de autenticación declara el bit **`digital_signature`** sin `non_repudiation`/`content_commitment`.

La etiqueta PKCS#11 (`CKA_LABEL`) solo se utiliza como mecanismo de respaldo si un certificado externo careciera de `KeyUsage`. Una vez elegido el certificado de firma en sesión pública, se conserva su `CKA_ID` para localizar la clave privada asociada (`CKO_PRIVATE_KEY`) tras iniciar sesión con el PIN.

---

### Pregunta 2: ¿Qué se envía a la TSA y por qué no el documento?
> *What exactly do you send to the TSA? Why not the document? What would a token over the document prove, and what would it not prove?*

En CAdES-T se envía a la TSA el **resumen criptográfico (SHA-256) del valor de la firma (`SignerInfo.signature`)**, nunca el resumen del documento original.

- **Qué demostraría un sello sobre el documento:** únicamente que el archivo existía antes de la hora $T$ indicada por la TSA. **No demostraría** quién lo firmó ni cuándo se realizó la firma: un firmante cuya clave caducase o fuese revocada hoy podría tomar un documento sellado hace un año, firmarlo hoy con su clave ya caducada/revocada y adjuntar aquel sello antiguo fingiendo que la firma se hizo hace un año.
- **Qué demuestra el sello sobre `signatureValue`:** como `signatureValue` depende criptográficamente de la clave privada del firmante y de `signedAttrs` (que a su vez contiene el `messageDigest` del documento y el hash del certificado en `signingCertificateV2`), sellar `SHA-256(signatureValue)` demuestra que **esa firma concreta sobre ese documento ya se había calculado no más tarde del instante $T$**.

---

### Pregunta 3: ¿Qué bytes firma realmente la tarjeta?
> *What bytes does the card actually sign? (Hint: it is not the document, and it is not exactly the DER encoding of the signed attributes as they appear in the file.)*

El proceso consta de tres niveles:
1. Primero se calcula el resumen `SHA-256` del documento y se coloca dentro del atributo firmado `messageDigest`.
2. Dentro del archivo `.csig`, el campo `signedAttrs` de `SignerInfo` aparece codificado en DER con la etiqueta contextual implícita `[0]` (primer byte **`0xA0`**). Sin embargo, según RFC 5652 §5.4, para calcular o verificar la firma se debe sustituir esa etiqueta contextual `[0]` (`0xA0`) por la etiqueta universal **`SET OF` (`0x31`)**, manteniendo sus elementos ordenados canónicamente según DER. Se calcula el `SHA-256` (32 bytes) de esa codificación `SET OF`.
3. Al invocar `C_Sign` en la tarjeta mediante el mecanismo PKCS#11 `CKM_RSA_PKCS`, la tarjeta no recibe el documento ni los 32 bytes desnudos del hash, sino la estructura ASN.1 DER **`DigestInfo`** de **51 bytes** (RFC 8017 §9.2), formada por los 19 bytes del `AlgorithmIdentifier` de SHA-256 (`30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`) seguidos de los 32 bytes del resumen `SHA-256(SET OF signedAttrs)`. El chip aplica el relleno PKCS#1 v1.5 de tipo `01` y la exponenciación modular con la clave privada.

---

### Pregunta 4: ¿Por qué se incluye `signingCertificateV2` y qué ataque previene?
> *Why is `signingCertificateV2` there? What attack does it prevent?*

En CMS clásico (RFC 5652), la firma cubre `signedAttrs`, pero el certificado del firmante (`SignedData.certificates`) y su referencia en `SignerInfo.sid` quedan **fuera** de los bytes firmados.

Sin `signingCertificateV2` (RFC 5035), un atacante o una CA maliciosa podría emitir un segundo certificado con **la misma clave pública** pero con otra identidad (otro `Subject`), otra política o distintos usos de clave, y sustituir el certificado dentro del `.csig`. La firma matemática RSA seguiría verificando con la clave pública. Al incluir el hash SHA-256 de los bytes DER completos del certificado dentro de `signingCertificateV2` en `signedAttrs`, el certificado exacto queda protegido por la firma y cualquier sustitución invalida la verificación.

---

### Pregunta 5: ¿Se puede confiar en los certificados incluidos en el `.csig`?
> *The signature file contains certificates. Can your verifier trust them? Where does trust come from?*

**No.** Cualquier atacante puede generar su propia CA autofirmada, emitir un certificado a nombre de otra persona, firmar un documento e incluir toda esa cadena dentro de `SignedData.certificates`.

La confianza nunca proviene del archivo `.csig`, sino de los **anclas de confianza (*Trust Anchors*)** que el verificador configura explícitamente fuera de banda mediante `--trust` (por ejemplo, `AC RAIZ DNIE 2` de la Policía Nacional y el certificado raíz de la TSA). Los certificados incluidos dentro del `.csig` sirven únicamente como eslabones auxiliares para construir el camino criptográfico desde el certificado hoja hasta un ancla de `--trust`. Si la cadena del firmante o de la TSA no termina en un certificado presente en `--trust`, el verificador nunca devuelve `VALID`, sino `INDETERMINATE`.

---

### Pregunta 6: Discrepancia entre la hora de la TSA y `signingTime`
> *The TSA says 10:42 and `signingTime` says 11:42. Which one wins, and why might they differ by one hour, or by three years?*

Gana siempre la **hora de la TSA (`genTime`)**:
- `signingTime` lo escribe el ordenador del firmante usando su propio reloj local. El firmante tiene control total sobre ese reloj (puede estar mal configurado o ser manipulado deliberadamente).
- Una diferencia de **una hora** (p. ej., `10:42 UTC` frente a `11:42`) suele deberse a una confusión de huso horario local (CET `UTC+1` en invierno en España) o al horario de verano (CEST) en un reloj mal sincronizado.
- Una diferencia de **tres años** puede deberse a una pila CMOS agotada, un reloj de sistema desajustado o un intento deliberado de antedatar (`backdating`) o posdatar la declaración de firma. Por ello, `notary verify` evalúa la vigencia de los certificados exclusivamente en la hora de la TSA (o en `--at`), y muestra `signingTime` únicamente como fecha declarada por el firmante.

---

### Pregunta 7: Certificado revocado hoy frente a una firma del mes pasado
> *A certificate is revoked today. Was a signature made last month valid? What information would you need to answer, and does OCSP give it to you?*

Para responder si una firma realizada el mes pasado era válida cuando el certificado figura revocado hoy, necesitamos saber:
1. **Cuándo se realizó realmente la firma:** acreditado por el sello de tiempo (`genTime`) de una TSA de confianza.
2. **Cuándo se produjo la revocación (`revocationTime`) y por qué motivo (`revocationReason`):** es decir, si la revocación fue posterior al sello de tiempo y si la clave ya estaba comprometida antes.

¿Nos da OCSP (RFC 6960) esta información?
- Cuando el estado devuelto en un `SingleResponse` OCSP es `revoked`, la estructura `RevokedInfo` incluye obligatoriamente el campo **`revocationTime`** (y opcionalmente `revocationReason`).
- Si `revocationTime` es **anterior o igual** a la hora de la TSA, la firma es con certeza **`INVALID`**, porque el certificado ya estaba revocado cuando se selló.
- Sin embargo, una consulta OCSP hecha hoy tiene limitaciones para validar firmas históricas:
  1. Si el certificado caducó hace tiempo, muchos responders OCSP dejan de mantener su estado o responden `unknown`.
  2. La fecha `revocationTime` refleja cuándo se notificó/registró la revocación ante la CA, pero si el usuario perdió la tarjeta días antes de denunciarlo, la clave pudo usarse en ese intervalo.
  3. Si `revocationTime` es **posterior** a la hora de evaluación (TSA o `--at`), `notary verify` mantiene la firma como válida: la firma ya existía, sellada, antes de la revocación. Sin sello de tiempo la hora de evaluación es la actual, de modo que cualquier revocación ya registrada invalida la prueba.
  4. Por eso los perfiles longevos (CAdES-LT / CAdES-LTA) incrustan la respuesta OCSP obtenida en el momento de firmar (o poco después del sello TSA) dentro de la propia firma para poder verificarla años más tarde sin depender del estado actual del servidor OCSP.

---

### Pregunta 8 y Sección Especial (1/2 página): ¿Qué demuestra un sello de tiempo y qué no demuestra?
> *What does your timestamp prove about the moment of signing? Could the signature have been made earlier? Could someone else have made it with your card?*

#### Qué demuestra exactamente una firma CAdES-T
Un sello de tiempo RFC 3161 emitido en el instante $T_{\text{TSA}}$ sobre el resumen `SHA-256(signatureValue)` establece una **cota temporal superior (*no más tarde de $T_{\text{TSA}}$*)**:
1. **Existencia previa del documento y de la firma:** Demuestra matemáticamente que tanto el documento (`messageDigest`) como la firma realizada con la clave privada asociada al certificado (`signingCertificateV2`) ya existían antes de $T_{\text{TSA}}$. Nadie —ni siquiera el propio titular de la clave privada— puede crear hoy una firma y conseguir que una TSA honesta le estampe una fecha del mes pasado.
2. **Orden causal entre creación, firma y sellado:** En toda prueba CAdES-T se cumple necesariamente que:
   $$T_{\text{creación del documento}} \;\le\; T_{\text{firma en tarjeta}} \;\le\; T_{\text{TSA}}$$
   En `notary sign`, al enviarse la petición a la TSA inmediatamente después de que la tarjeta genera `signatureValue` y con un `nonce` fresco de 64 bits, $T_{\text{firma}}$ y $T_{\text{TSA}}$ distan apenas unos segundos en condiciones normales.

#### Qué NO demuestra un sello de tiempo
1. **No establece una cota inferior (*cuánto antes se firmó*):** El sello RFC 3161 sobre `signatureValue` prueba que la firma no se hizo *después* de $T_{\text{TSA}}$, pero **la firma sí pudo haberse calculado horas, días o meses antes** de enviarse a la TSA. Un firmante podría firmar un documento en enero, guardar el `.csig` en privado y pedir el sello a la TSA en marzo; el sello solo probará que en marzo la firma ya existía, no que se firmase en marzo (para acotar también el límite inferior haría falta incluir antes de firmar un dato impredecible reciente, como un bloque o un primer sello previo dentro de los datos firmados).
2. **No demuestra quién pulsó físicamente el teclado ni la ausencia de coacción:** La firma con el DNIe demuestra que intervino el chip físico del DNIe y que se introdujo su PIN correcto. No demuestra por sí sola que el titular no prestara su tarjeta y su PIN a un tercero, que un malware en el ordenador no modificase los bytes mostrados en pantalla antes de enviar el hash al lector (*what you see is not what you sign*), ni que el titular firmara libremente y sin coacción.

---

## 3. Reglas de Decisión del Verificador (`notary verify`)

El comando `notary verify` ejecuta los 8 pasos en orden y emite uno de los tres veredictos posibles sin lanzar nunca excepciones no controladas:

| Veredicto | Código de salida | Condiciones que lo producen |
| :--- | :---: | :--- |
| **`VALID`** | `0` | 1. El contenedor `.csig` es CMS `SignedData` válido (`detached` o `attached`).<br>2. `messageDigest` coincide con el hash del documento.<br>3. `signingCertificateV2` (o `signingCertificate`) coincide con el certificado del firmante.<br>4. La firma matemática sobre `SET OF` (`0x31`) de `signedAttrs` es válida.<br>5. La cadena del firmante es criptográficamente válida hasta un ancla de `--trust`.<br>6. Si hay `signatureTimeStampToken`, su `messageImprint` es `Hash(signatureValue)`, su firma CMS y `ExtendedKeyUsage = timeStamping` son válidos, y la cadena de la TSA llega a un ancla de `--trust`. (Si no hay sello, se avisa explícitamente de que la única hora es una declaración).<br>7. Todos los certificados eran vigentes en la hora de la TSA (o en `--at`).<br>8. El estado OCSP es `GOOD` (o el certificado no declara URL OCSP en AIA). |
| **`INVALID`** | `1` | Archivo vacío, truncado o corrupto; falta `--content` en una firma `detached`; el documento fue modificado (`messageDigest` distinto); `signingCertificateV2` no coincide; firma RSA/ECDSA inválida; un emisor de la cadena no es CA o su firma falla; el sello TSA cubre el documento en vez de la firma o pertenece a otra firma; algún certificado estaba caducado o aún no válido en la hora de evaluación; o OCSP devuelve `REVOKED` (o firma OCSP inválida). |
| **`INDETERMINATE`** | `2` | La firma y los hashes son íntegros, pero falta información externa para confirmar la confianza o la vigencia: no se indicó `--trust`, la cadena del firmante o de la TSA no enlaza con ningún certificado de `--trust`, el servidor OCSP es inalcanzable por red o responde `UNKNOWN`. |

---

### Robustez ante archivos malformados

`notary verify` nunca termina con una excepción: `asn1crypto` parsea de forma perezosa y un archivo corrupto puede fallar en cualquier punto de la verificación, no solo al cargarlo. `run_verify` envuelve todo el proceso y convierte cualquier excepción inesperada en `INVALID` con el motivo. Se comprueba con un test que muta bytes al azar (*fuzzing*) y exige siempre un veredicto. Los cambios en la lista informativa `digestAlgorithms` del contenedor CMS no alteran el veredicto, porque el verificador usa el algoritmo del `SignerInfo`, que sí está firmado.

### PAdES: firma dentro de un PDF

- **Estructura.** `sign --format pades` no reescribe el PDF: añade una *actualización incremental* con (1) el diccionario de firma (`/Type /Sig`, `/Filter /Adobe.PPKLite`, `/SubFilter /ETSI.CAdES.detached`, `/ByteRange`, `/Contents`, `/M`), (2) un campo de firma invisible (`/FT /Sig`, widget con `/Rect [0 0 0 0]`), (3) el catálogo y la página modificados (`/AcroForm`, `/Annots`) y (4) una tabla de referencias nueva que apunta a la anterior con `/Prev`. Si el PDF original usa *xref stream*, la nueva sección también (un PDF con tabla clásica recibe tabla clásica). Las firmas anteriores siguen verificando porque sus bytes no cambian.
- **Qué firma la tarjeta.** El valor `/Contents` se reserva con ceros (20 000 bytes) y `/ByteRange [0 a b c]` se rellena con la posición real tras construir el archivo. El CMS es el mismo CAdES detached de siempre, calculado sobre los bytes del PDF fuera del hueco, con el sello RFC 3161 sobre el valor de firma. Dentro del CMS **no hay `signingTime`**: en PAdES la fecha declarada es `/M` (ETSI EN 319 142-1). Si el CMS no cabe en la reserva, `sign` falla en lugar de truncarlo.
- **Verificación.** `verify` detecta el PDF por su cabecera, localiza cada `/ByteRange` y exige: que empiece en 0; que el hueco sea exactamente el valor hexadecimal que sigue a `/Contents` (así no se puede apuntar el rango a otro sitio, ataque de *signature wrapping*); y que, tras la **última** firma, no quede ningún byte sin cubrir. Una firma intermedia puede no llegar al final del archivo solo porque otra posterior la cubre. Después aplica a cada firma los mismos pasos que a un `.csig` (resumen, firma, cadena, sello, vigencia, OCSP). Se aceptan también `adbe.pkcs7.detached` (lo que genera Acrobat por defecto), sin `signingCertificateV2`, avisando de que entonces no se puede comprobar ese vínculo.
- **Decisión: bytes añadidos tras la firma = `INVALID`.** Un validador completo (por ejemplo pyHanko) distingue qué cambios posteriores están permitidos (relleno de formularios, nuevas firmas) según los permisos del documento (DocMDP). Aquí no se analizan, así que cualquier contenido no cubierto se rechaza: es la postura conservadora, a costa de rechazar PDF que otro validador aceptaría para su revisión original.
- **Contraste independiente.** Se firmó un PDF con `notary` y se validó con pyHanko (fuera del programa, solo para comprobar): firma íntegra, válida y de confianza, con cobertura de todo el archivo, para PDF clásicos, con *xref stream* y con catálogo y páginas dentro de *object streams*; y con doble firma. En el sentido inverso, `notary verify` acepta un PAdES firmado por pyHanko. Un byte cambiado en el contenido lo detectan los dos.
- **Biblioteca.** Se usa `pypdf` solo para *leer* el catálogo, la página y el trailer (el guion permite una biblioteca para la estructura del PDF, no para firmar). Escribir la actualización incremental, el `/ByteRange`, la firma, el sello y la verificación es código propio.

### Protección del PIN: el contador de intentos no se puede consultar

- **Problema.** El DNIe permite 3 PIN incorrectos seguidos antes de bloquearse, y el guion (§4.4) exige no gastar el último. La comprobación obvia es el flag PKCS#11 `CKF_USER_PIN_FINAL_TRY`, pero **con este DNIe no es fiable**: OpenSC 0.27.1 (`card-dnie.c`) no soporta la consulta de estado del PIN (`SC_PIN_CMD_GET_INFO` devuelve `NOT_SUPPORTED`) y la tarjeta solo informa de los intentos restantes (`SW 63Cx`) como respuesta a un PIN **incorrecto**. Por eso, en una sesión nueva el flag aparece inactivo aunque ya se hayan gastado intentos. Se observó con una tarjeta real: tras dos PIN erróneos, `notary info` seguía mostrando `USER_PIN_FINAL_TRY` inactivo.
- **Por qué no se pregunta a la tarjeta.** Un `VERIFY` sin datos es la consulta estándar de ISO 7816-4, pero el DNIe exige un canal seguro cifrado (CWA) para cualquier comando; improvisarlo contra una tarjeta con pocos intentos restantes sería peor que el problema.
- **Solución: contador local (`notary/pin_guard.py`).** `PKCS11Signer` registra cada `CKR_PIN_INCORRECT` y, tras 2 fallos seguidos, se niega a pedir el PIN (deja un intento de margen). Un PIN correcto reinicia la cuenta; `CKR_PIN_LOCKED` la fija en 3. Solo se guarda el número de fallos por tarjeta, identificada por un hash de su número de serie, **nunca el PIN**. Si el fichero de estado no se puede leer, se rechaza en lugar de suponer 0. El comando `notary pin-guard` muestra el contador y permite fijarlo (`--set N`) o reiniciarlo (`--reset`) sin pedir el PIN.
- **Limitación.** Solo cuenta los intentos hechos con `notary`: los de AutoFirma, un navegador u otro programa no los ve, y si se cambia el PIN en un PAD hay que reiniciarlo a mano. Es una red de seguridad, no una garantía.

### Evidencia incrustada (LTV) y varias firmas

- **Respuesta OCSP incrustada:** si la firma lleva sello de tiempo y una respuesta OCSP para el certificado del firmante, `verify` la usa **sin red**. Se valida igual que una respuesta en vivo (firma del emisor o de un responder delegado con EKU `OCSPSigning`, `CertID`, estado) y además debe haberse **producido después del sello de tiempo**: una respuesta anterior solo dice que el certificado estaba bien *antes* y no descarta una revocación entre medias, así que el veredicto es `INDETERMINATE`. Una respuesta incrustada que dice `revoked` con `revocationTime` anterior a la hora de evaluación da `INVALID`. Sin evidencia incrustada, `verify` consulta OCSP en vivo como antes. Los certificados de `certificateValues` sirven para completar la cadena; la confianza sigue viniendo solo de `--trust`.
- **Frescura de la respuesta en vivo:** la petición lleva un nonce aleatorio de 16 bytes; si la respuesta trae otro nonce es `INVALID`, y si no trae ninguno se acepta (muchos responders no lo soportan, p. ej. se desconoce si el del DNIe lo hace). Además, la hora actual debe caer dentro de `thisUpdate`–`nextUpdate` (margen de 5 minutos); una respuesta caducada o del futuro es `INDETERMINATE`. Sin `nextUpdate` se exige que tenga menos de 24 horas.
- **Varias firmas:** si el archivo tiene más de un `SignerInfo`, `verify` los comprueba uno a uno y muestra cada desglose. El veredicto final es el peor de todos (`INVALID` > `INDETERMINATE` > `VALID`), de modo que una sola firma defectuosa invalida el conjunto. El orden en que se muestran lo fija la codificación DER (`SET OF` se ordena por bytes), no el orden en que se firmó.
- **CA emisoras:** además de `BasicConstraints CA=TRUE`, si el certificado declara `KeyUsage` debe incluir `keyCertSign`.

## 4. Limitaciones Conocidas

1. **CAdES-LT, no CAdES-LTA:** con `--ltv` se incrustan la cadena y la respuesta OCSP del firmante, pero no se incrustan los de la TSA (su cadena ya viaja en el token con `certReq`) ni se añaden sellos de archivo (`archiveTimeStamp`). Si el certificado de la TSA caduca sin resellar, la prueba deja de poder verificarse en el futuro; haría falta CAdES-LTA.
2. **Contrafirmas anidadas:** `cosign` añade firmas en paralelo, no contrafirmas (`countersignature`).
3. **PAdES básico:** la firma es invisible (sin aspecto sobre la página); no hay PAdES-LT/LTA (no se escribe el diccionario `/DSS` con la cadena y el OCSP, por eso `--format pades` no admite `--ltv`); no se admiten PDF cifrados; la firma se coloca en la primera página; no se analizan los permisos DocMDP, así que cualquier modificación posterior a la última firma se rechaza.
4. **Nonce OCSP no obligatorio:** si el servidor no devuelve el nonce, la protección frente a repeticiones se reduce a la ventana `thisUpdate`/`nextUpdate`.
5. **DNIe Remote no consigue firmar:** el móvil como lector (`DNIeRemotePKCS11.dll`) lee los certificados, pero la firma falla en el paso del PIN. Se probó en dos equipos. En el primero el programa se quedó parado en `C_Login` hasta cortarlo con Ctrl+C. En el segundo (3-nov-2026, con el DNIe vinculado por USB) `C_Login` devolvió `Unknown error (0x000000E9)`, que no es un código estándar de PKCS#11, y la app del móvil mostró «the operation cannot be successfully finished». Allí `PROTECTED_AUTHENTICATION_PATH` salía inactivo, así que `notary` pedía el PIN por consola. No sabemos si el PIN llegó a la tarjeta ni por qué falla el módulo. Con el lector USB y OpenSC todo funciona. `PKCS11Signer` respeta ahora `CKF_PROTECTED_AUTHENTICATION_PATH` (llama a `C_Login` con NULL y no pide el PIN por consola) y cuenta como intento gastado un `login` interrumpido con Ctrl+C, pero no sabemos si esa era la causa del bloqueo. El contador de PIN solo cuenta `CKR_PIN_INCORRECT`, y no sabemos qué código devuelve ese módulo con un PIN erróneo, así que con el móvil podría contar menos intentos de los gastados. Con un único módulo instalado, `find_pkcs11_module` lo devuelve sin sondearlo (cargar el módulo dos veces rompe la comunicación de DNIe Remote), de modo que la ausencia de tarjeta se detecta después, al listar las ranuras.
6. **Verificación de estado OCSP del firmante:** Se consulta por OCSP el certificado del firmante extrayendo la URL de su extensión AIA (`AuthorityInformationAccess`); para las raíces de confianza (`--trust`) la confianza es directa por configuración del usuario.

