# Guía de pruebas de `notary` con el DNIe

Pasos para probar **todo** el programa con un DNIe real, de forma limpia y en orden. Está pensada para quien parte de cero con su propia tarjeta. Al final hay una tabla para anotar los resultados.

> **Qué se prueba:** `info`, firma CAdES-T (separada y adjunta), `verify` contra las TSA reales y el OCSP del DNIe, interoperabilidad con OpenSSL / AutoFirma / VALIDe, casos que deben fallar, CAdES-LT (`--ltv`), PAdES (PDF), varias firmas (`cosign`), intercambio de pruebas con el *forger* y la firma del ZIP de entrega.

---

## 0. Reglas del PIN (léelas antes de empezar)

El DNIe se bloquea tras **3 PIN incorrectos seguidos**, y solo se desbloquea en un Punto de Actualización del DNIe (PAD), con la huella. Con este DNIe no se puede consultar cuántos intentos quedan.

1. **Si un PIN falla, no lo reintentes.** Para, y comprueba el PIN en un PAD.
2. `notary` cuenta los fallos y, tras **2 seguidos**, se niega a pedir el PIN. Es la protección funcionando, no un error.
3. El PIN solo lo escribes tú, en tu terminal, cuando `notary` lo pide (no se ve al escribir). No lo pegues en ningún chat, fichero ni comando.
4. Si dudas del PIN, no pruebes «a ver si es este»: ve al PAD.
5. Cierra AutoFirma, Firefox y cualquier programa que pueda tener la tarjeta abierta antes de probar.

Si ya fallaste algún intento fuera de `notary` (AutoFirma, un navegador…), díselo al programa: `notary pin-guard --set N` (con N = fallos gastados).

---

## 1. Preparación (una sola vez)

### 1.1 Código y entorno

```powershell
cd <carpeta-del-repositorio>
git pull
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # si PowerShell lo bloquea: usa  .\.venv\Scripts\python.exe -m notary ...  en lugar de  notary ...
pip install -e .
python -m unittest discover -s tests   # debe terminar en OK (143 pruebas), sin tocar la tarjeta
```

### 1.2 OpenSC y lector

```powershell
winget install --id OpenSC.OpenSC --source winget
```

Conecta el lector y coloca el DNIe **con el chip hacia arriba, en contacto con el lector**. Si no responde, vuelve a colocarlo y limpia los contactos. Comprobación sin PIN:

```powershell
& "C:\Program Files\OpenSC Project\OpenSC\tools\opensc-tool.exe" -n      # debe imprimir:  dnie
```

### 1.3 Carpeta de trabajo y certificados de confianza

**Fuera del repositorio**: las pruebas firmadas con tu DNIe contienen tu nombre y tu número de DNI y no deben acabar en git. La carpeta queda así: `firmas_propias\` (tus firmas y documentos), `intercambio\` (las pruebas que preparas y las que recibes), `trust\` y `evidencia\`.

```powershell
$W = "$HOME\notary-dnie"; $MIS = "$W\firmas_propias"   # $MIS: tus firmas y documentos
New-Item -ItemType Directory -Force "$W\trust","$MIS","$W\intercambio" | Out-Null
"Documento de prueba de la practica A1 Notary." | Set-Content "$MIS\doc.txt"

# Raíz y CA intermedias del DNIe (PEM). Sirve cualquier AC DNIE 004/005/006; descarga las tres.
foreach ($f in "ACRaiz2","AC004","AC005","AC006") {
  Invoke-WebRequest "http://pki.policia.es/dnie/certs/$f.crt" -OutFile "$W\trust\$f.crt" }
# Raíz de FreeTSA y raíces públicas (DigiCert y Sectigo) para verificar los sellos de tiempo
Invoke-WebRequest "https://freetsa.org/files/cacert.pem" -OutFile "$W\trust\freetsa_root.pem"
Copy-Item (python -c "import certifi; print(certifi.where())") "$W\trust\raices_publicas.pem"
```

> Si `notary info` muestra una CA emisora que no es AC DNIE 004/005/006, descarga su certificado de `http://pki.policia.es/dnie/certs/` a la misma carpeta.

Para acortar los comandos de verificación:

```powershell
$T = Get-ChildItem "$W\trust" | ForEach-Object FullName     # todos los certificados de confianza
```

### 1.4 Red: cable (Ethernet) o Wi-Fi

Todo lo que no es DNIe Remote funciona igual por cable que por Wi-Fi. Solo hace falta salida a Internet por los puertos 80 y 443 hacia las TSA, el OCSP del DNIe y la PKI de la Policía. Compruébalo antes de empezar:

```powershell
foreach ($d in @(@("freetsa.org",443), @("timestamp.digicert.com",80), @("timestamp.sectigo.com",80), @("ocsp.dnie.es",80), @("pki.policia.es",80))) {
  $ok = Test-NetConnection -ComputerName $d[0] -Port $d[1] -InformationLevel Quiet -WarningAction SilentlyContinue
  "{0,-26} puerto {1,-4} {2}" -f $d[0], $d[1], $(if ($ok) { "OK" } else { "FALLA" })
}
```

**Debe salir** `OK` en las cinco líneas. Si alguna falla, esa red bloquea el puerto, algo habitual en redes de universidad o de empresa. Prueba con otra red, por ejemplo con el punto de acceso del móvil. Si solo falla FreeTSA, no es grave: `notary` pasa a la siguiente TSA (paso 6). Si falla `ocsp.dnie.es`, `verify` dará `INDETERMINATE`.

Para saber por qué adaptador sales a Internet:

```powershell
Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, LinkSpeed | Format-Table -AutoSize
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize
```

Un PC puede mostrar varios adaptadores a la vez. Los `vEthernet` (Hyper-V, WSL), los de Docker y los de VPN son virtuales. El que cuenta es el de tu cable o el de tu Wi-Fi, que lleva la IP de tu router (normalmente `192.168.x.x`).

### 1.5 Alternativa: el móvil como lector (DNIe Remote)

Si no tienes lector USB, el móvil con NFC puede hacer de lector con la aplicación **DNIeRemote** de la Policía (una parte para Windows y otra para Android). **En este proyecto no ha funcionado** para firmar: se probó en dos equipos. Lee los certificados (`notary info` los muestra), pero el paso del PIN falla: en un equipo se quedó parado y en el otro `C_Login` devolvió `Unknown error (0x000000E9)` y la app del móvil dijo «the operation cannot be successfully finished». Si lo pruebas, hazlo solo para comprobarlo y con un solo intento. Para firmar, usa el lector USB con OpenSC.

Instalación: el instalador de DNIe Remote (`Instalador_DNIeRemote_x64.exe`) se niega a instalarse («ya hay una versión más reciente») si está instalado el «Instalable DNIe» de las tarjetas con lector. Hay que desinstalar ese primero. Al terminar existe `C:\Windows\System32\DNIeRemotePKCS11.dll` y el servicio `DNIeRemoteSvc`. La app del móvil se llama DNIeSmartConnect, y no es MiDNI. Lo que sí dice el [manual oficial](https://www.dnielectronico.es/PDFs/DNIeRemote_user_manual.pdf) (v1.3.28, 2020):

- El PC y el móvil se vinculan por **USB** (con la depuración USB activada y la transferencia de archivos MTP) o por **Wi-Fi** (el móvil escanea el código QR que muestra el asistente de Windows).
- **USB no usa la red**, así que funciona igual con el PC por cable, por Wi-Fi o sin red. Es la primera opción si el emparejamiento por Wi-Fi da problemas.
- Con Wi-Fi, PC y móvil deben estar **en la misma red**. No basta con que los dos tengan Internet. Si el QR da «La información recuperada no es válida», el manual dice que la causa es que no lo están.
- La comunicación va por un canal seguro y el manual dice que da igual que la red sea pública o privada. Aun así, si el emparejamiento por Wi-Fi tarda más de 10 segundos, el manual apunta al **cortafuegos de Windows** y pide comprobar que existe una regla para DNIeRemote.
- El módulo PKCS#11 es `DNIeRemotePKCS11.dll`, en `C:\Windows\System32\`. Si es el único módulo instalado, `notary` lo usa solo. Si tienes también OpenSC, indícalo: `--module "C:\Windows\System32\DNIeRemotePKCS11.dll"`.
- **No es 100 % compatible con AutoFirma.** El manual dice que solo se puede firmar directamente desde el almacén de Mozilla Firefox, y que AutoFirma necesita la opción `-store mozilla` por línea de comandos. Esto afecta solo a *firmar con AutoFirma*. Para **verificar** en AutoFirma o VALIDe no hace falta ningún lector.

**Si `notary sign` se queda parado en «Conectando con el DNIe y verificando PIN...».** Le pasó a la pareja con el PC por cable y el móvil por Wi-Fi, en la misma red. El programa llegó a leer los certificados a través del móvil, así que la vinculación y la red funcionaban, y la llamada `C_Login` del módulo no volvió hasta que se cortó con Ctrl+C. Por tanto el problema está en el paso del PIN y no en la red. Antes de cortar, mira:

- Si hay una **ventana** de DNIe Remote pidiendo el PIN, quizá detrás de otras, o una **petición en el móvil**.
- Qué dice `notary info` en `PROTECTED_AUTHENTICATION_PATH`. Si está `ACTIVO`, el módulo espera el PIN fuera del terminal y `notary` ya no lo pide por consola: se lo pasa al módulo como indica el estándar PKCS#11 y te avisa de que lo escribas en la ventana, el teclado del lector o el móvil. **No lo hemos podido probar con DNIe Remote.**
- Si cortas con Ctrl+C durante ese paso, `notary` lo **cuenta como un intento de PIN**, porque no sabe si el PIN llegó a la tarjeta. Si cortaste con una versión anterior del programa, ese intento no se contó: ajusta el contador con `notary pin-guard --set N` y, si dudas, comprueba el PIN en un PAD antes de seguir.

Para problemas de **emparejamiento**, el manual asocia cada mensaje a una causa:

- «La información recuperada no es válida» al escanear el QR apunta a que PC y móvil no están en la misma red.
- Un emparejamiento por Wi-Fi que tarda más de 10 segundos apunta al cortafuegos de Windows.
- «Error de comunicación. Se ha perdido la conexión con el DNIe» al acercar el DNI al móvil apunta al NFC. El manual dice que es muy frágil, de muy corto alcance y que hay que colocar el DNI justo sobre la antena del móvil, sin moverlo.

**Para separar la red del resto, vincula por USB**, que no usa la red. Con la red como sospechosa, comprueba que el router no aísle a los clientes ni use una red de invitados, y compara la IPv4 del PC con la del móvil (Ajustes, Wi-Fi, tu red). Con máscara `/24`, que es lo habitual, coinciden los tres primeros números (por ejemplo `192.168.1.x`).

**PC con adaptadores virtuales.** *Esto es una hipótesis nuestra y no aparece en el manual.* Si DNIeRemote anunciara la IP de un adaptador virtual (Hyper-V, WSL, VPN), el móvil no podría alcanzar el PC. Si el emparejamiento falla y tu PC tiene varios adaptadores, desactiva los virtuales y las VPN mientras vinculas, o usa USB.

**Cortafuegos.** Para ver si existe la regla de DNIeRemote y a qué tipo de red se aplica, y qué tipo de red tienes:

```powershell
Get-NetFirewallApplicationFilter | Where-Object { $_.Program -like '*DNIeRemote*' } | Get-NetFirewallRule | Format-Table DisplayName, Enabled, Direction, Action, Profile -AutoSize
Get-NetConnectionProfile | Format-Table Name, InterfaceAlias, NetworkCategory -AutoSize
```

Si la regla solo cubre el perfil `Private` y tu red es `Public`, el cortafuegos bloquea la conexión. Tienes tres salidas: vincular por USB, pasar esa red a Privada (relaja el cortafuegos de esa red) o ampliar el perfil de la regla. Esa decisión es tuya, y por eso `notary` no la toma por ti.

Para comprobar o arrancar los servicios de Windows (`SCardSvr` y `DNIeRemoteSvc`) como administrador se puede ejecutar `Start-Service SCardSvr, DNIeRemoteSvc` y consultar `Get-Service SCardSvr, DNIeRemoteSvc`. El manual oficial no menciona ningún servicio llamado `DNIeRemoteSvc`, aunque el instalador de DNIe Remote lo registra en Windows.

Con el móvil, el contador de PIN de `notary` puede quedarse corto. Solo cuenta el error `CKR_PIN_INCORRECT`, y no sabemos qué código devuelve DNIe Remote con un PIN erróneo. Si un intento falla con otro error, mira `notary pin-guard` y trátalo como un intento gastado.

---

## 2. Reconocer la tarjeta (no pide PIN)

```powershell
notary info
notary pin-guard
```

**Debe salir:** un token «DNI electrónico», los certificados `CertAutenticacion` (uso `digital_signature`) y `CertFirmaDigital` (uso `non_repudiation`) con su emisor (`AC DNIE 00X`) y su validez, y `USER_PIN_LOCKED` / `USER_PIN_FINAL_TRY` inactivos. `pin-guard` debe decir `0 de 3`.

> **Comprueba que los certificados no estén caducados.** Si lo están, hay que renovarlos en un PAD antes de seguir.

---

## 3. Firma básica CAdES-T con el DNIe

```powershell
notary sign "$MIS\doc.txt"
```

Te pide `Introduce el PIN del DNIe:` (una sola vez). Puede abrirse una ventana de OpenSC que pide confirmar la firma: acéptala. Hace la firma en la tarjeta, pide el sello de tiempo a FreeTSA y escribe `doc.txt.csig`.

**Debe salir:** los pasos `[1]` a `[6]`, `sellado por https://freetsa.org/tsr`, `Resultado ... CAdES-T` y `Escrito ... doc.txt.csig`.

## 4. Verificar tu propia firma

```powershell
notary verify "$MIS\doc.txt.csig" --content "$MIS\doc.txt" --trust $T
```

**Debe salir** `VEREDICTO: VALID — firmado por <tu nombre> (FIRMA), no más tarde de <hora UTC>`, con:

- `[4]` firma RSA PKCS#1 v1.5 / SHA256;
- `[5]` cadena `... (FIRMA) -> AC DNIE 00X -> AC RAIZ DNIE 2`;
- `[6]` el sello de FreeTSA y su cadena;
- `[8]` OCSP `GOOD (http://ocsp.dnie.es)`.

> El OCSP del DNIe responde por HTTP (no por HTTPS) y devuelve el nonce; la respuesta es válida durante una hora.

## 5. Firma adjunta (attached)

```powershell
notary sign "$MIS\doc.txt" --format attached --out "$MIS\doc_attached.csig"
notary verify "$MIS\doc_attached.csig" --trust $T
```

Sin `--content`, porque el documento va dentro. **Debe salir** `VALID`.

## 6. Varias TSA: si la primera falla, usa la siguiente

```powershell
notary sign "$MIS\doc.txt" --tsa http://tsa-que-no-existe.invalid https://freetsa.org/tsr --out "$MIS\doc_tsa2.csig"
```

**Debe salir:** `fallo (...)` para la primera y `sellado por https://freetsa.org/tsr`. Opcional: repite con `http://timestamp.digicert.com` y `http://timestamp.sectigo.com`, y verifica cada uno (cada TSA rellena el token de forma distinta).

---

## 7. Interoperabilidad con herramientas oficiales

### 7.1 OpenSSL (a mano)

```powershell
openssl cms -verify -binary -inform DER -in "$MIS\doc.txt.csig" -content "$MIS\doc.txt" -noverify -out "$MIS\verificado.bin"
```

**Debe salir:** `CMS Verification successful`. (`-noverify` omite la cadena; lo que se comprueba aquí es la firma.) Windows PowerShell 5.1 muestra ese mensaje con aspecto de error rojo porque OpenSSL lo escribe por el canal de errores; si dice `successful`, ha ido bien. Si tu OpenSSL no está en el PATH, usa el de Git: `C:\Program Files\Git\usr\bin\openssl.exe`.

### 7.2 AutoFirma y VALIDe

- **AutoFirma:** *Verificar firma* → elige `doc.txt.csig` y, si lo pide, `doc.txt`. Debe dar firma válida.
- **VALIDe** (`https://valide.redsara.es`): *Validar firma* → sube la firma y el documento.
- **Haz una captura de cada una**:.

---

## 8. Casos que deben fallar

Todos sobre la misma firma. Ninguno usa la tarjeta.

```powershell
# 8.1 Documento modificado  ->  INVALID (el resumen no coincide)
"otro contenido" | Set-Content "$MIS\otro.txt"
notary verify "$MIS\doc.txt.csig" --content "$MIS\otro.txt" --trust $T

# 8.2 Sin certificados de confianza  ->  INDETERMINATE (no se puede validar la cadena)
notary verify "$MIS\doc.txt.csig" --content "$MIS\doc.txt"

# 8.3 Evaluada antes de que existiera tu certificado (ponlo a una fecha anterior a su "Válido desde")  ->  INVALID
notary verify "$MIS\doc.txt.csig" --content "$MIS\doc.txt" --trust $T --at 2020-01-01T00:00:00Z

# 8.4 Archivo truncado  ->  INVALID, sin excepciones
$b = [IO.File]::ReadAllBytes("$MIS\doc.txt.csig"); [IO.File]::WriteAllBytes("$MIS\truncada.csig", $b[0..($b.Length-41)])
notary verify "$MIS\truncada.csig" --content "$MIS\doc.txt" --trust $T

# 8.5 Firma separada sin indicar el documento  ->  INVALID (pide --content)
notary verify "$MIS\doc.txt.csig" --trust $T
```

Códigos de salida: `0` = VALID, `1` = INVALID, `2` = INDETERMINATE (`$LASTEXITCODE`).

---

## 9. CAdES-LT: evidencia dentro de la firma (`--ltv`)

```powershell
notary sign "$MIS\doc.txt" --ltv --out "$MIS\doc_ltv.csig"
```

Descarga la CA emisora de la AIA de tu certificado, pide una respuesta OCSP y las incrusta tras el sello. **Debe salir** `Resultado ... CAdES-LT`. Si no puede reunir la evidencia (por ejemplo, sin red), falla con un mensaje `[!]` y **no escribe ningún fichero**. Este es el paso que más depende del DNIe real: si falla, pega la salida completa.

Después, **desconecta toda la red** y verifica. Si tu PC tiene cable y Wi-Fi a la vez, hay que cortar los dos: desenchufa el cable y apaga el Wi-Fi (en un portátil, el modo avión lo hace todo). Comprueba que de verdad estás sin red, porque con una conexión que sigue activa la prueba no demuestra nada:

```powershell
Test-NetConnection ocsp.dnie.es -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue     # debe dar False
notary verify "$MIS\doc_ltv.csig" --content "$MIS\doc.txt" --trust $T
```

Con permisos de administrador también puedes usar `Disable-NetAdapter -Name "Wi-Fi" -Confirm:$false` y volver con `Enable-NetAdapter -Name "Wi-Fi"` (el nombre del adaptador sale de `Get-NetAdapter`).

**Debe salir** `VALID` con `[8] ... GOOD (incrustada en la firma, LTV; verificada sin red)`. Vuelve a conectar la red cuando termines.

> Comprobación de contraste: `doc.txt.csig` (sin `--ltv`) verificado **sin red** debe dar `INDETERMINATE`, porque no puede consultar el OCSP.

---

## 10. PAdES: firmar dentro de un PDF

Usa cualquier PDF (`$MIS\ejemplo.pdf`).

```powershell
notary sign "$MIS\ejemplo.pdf" --format pades          # escribe ejemplo.signed.pdf
notary verify "$MIS\ejemplo.signed.pdf" --trust $T
```

**Debe salir** `[1] Formato ... PAdES (ETSI.CAdES.detached)` y `VALID`. Abre `ejemplo.signed.pdf` en un lector de PDF (Adobe Acrobat, AutoFirma o VALIDe) y mira el panel de firmas. **Captura de pantalla.**

> La firma es invisible (no se dibuja sobre la página): se ve en el panel de firmas del lector. Si Acrobat dice que la identidad no es de confianza, es normal: no tiene la raíz del DNIe instalada.

Prueba negativa: añade texto al final del PDF firmado y verifica; **debe dar** `INVALID` (`bytes añadidos después de la última firma`).

```powershell
Add-Content "$MIS\ejemplo.signed.pdf" "contenido anadido"
notary verify "$MIS\ejemplo.signed.pdf" --trust $T
```

---

## 11. Varias firmas (`cosign`)

Necesita **dos firmantes**: el DNIe de cada miembro de la pareja (o, para probar solo, el firmante software). Sirve para comprobar que `verify` muestra todos.

```powershell
# El miembro A firma como en el paso 3 (doc.txt.csig). El miembro B añade su firma con SU DNIe y SU PIN:
notary cosign "$MIS\doc.txt.csig" "$MIS\doc.txt" --out "$MIS\doc_dos_firmas.csig"
notary verify "$MIS\doc_dos_firmas.csig" --content "$MIS\doc.txt" --trust $T
```

**Debe salir:** `=== Firmante 1 de 2 ===`, `=== Firmante 2 de 2 ===` y `VEREDICTO FINAL: VALID (2 firmantes; ...)`. La firma original no se modifica.

Para un PDF, basta con volver a firmar el PDF ya firmado (paso 10) con el otro DNIe.

---

## Tabla de resultados

| # | Prueba | Resultado esperado | ¿OK? | Notas |
| --- | --- | --- | --- | --- |
| 1.4 | Diagnóstico de red (cable o Wi-Fi) | `OK` en las cinco líneas | ☐ | |
| 2 | `notary info` y `pin-guard` | tarjeta y certificados vigentes; `0 de 3` | ☐ | |
| 3 | `sign` detached | `CAdES-T`, sellado por FreeTSA | ☐ | |
| 4 | `verify` propia | `VALID`, OCSP `GOOD` | ☐ | |
| 5 | `sign` + `verify` attached | `VALID` | ☐ | |
| 6 | Cambio de TSA | falla la 1.ª, sella la 2.ª | ☐ | |
| 7.1 | OpenSSL | `CMS Verification successful` | ☐ | |
| 7.2 | AutoFirma / VALIDe | firma válida (captura) | ☐ | |
| 8.1–8.5 | Casos negativos | INVALID / INDETERMINATE según el caso | ☐ | |
| 9 | `--ltv` y verificación sin red | `VALID`, «incrustada en la firma» | ☐ | |
| 10 | PAdES | `VALID` y visible en el lector (captura) | ☐ | |
| 11 | `cosign` | `VEREDICTO FINAL: VALID (2 firmantes)` | ☐ | |
| 13.2 | ZIP firmado por ambos | `VALID` | ☐ | |

---

## Si algo falla

| Síntoma | Qué hacer |
| --- | --- |
| `No se han encontrado módulos PKCS#11` | Instala OpenSC (1.2), o DNIe Remote (1.5), o indica el módulo con `--module "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"`. |
| `ninguno detecta un token presente`, `CKR_DEVICE_ERROR`, `Unresponsive card` | Recoloca el DNIe con el chip hacia arriba, limpia los contactos y cierra AutoFirma/Firefox. Comprueba con `opensc-tool -n` (debe decir `dnie`). |
| `notary se niega a pedir el PIN` / `Se han registrado N PIN incorrectos` | Es la protección. **No la saltes:** comprueba el PIN en un PAD y luego `notary pin-guard --reset`. |
| `CKR_PIN_INCORRECT` | **Para.** No reintentes. Revisa el PIN en un PAD. |
| `INDETERMINATE ... no se encuentra el certificado emisor` | Falta una CA en `--trust`: añade `AC DNIE 00X`, `ACRaiz2` o la raíz de la TSA. |
| `INDETERMINATE` por OCSP | Sin red, o el servidor no responde. Reintenta más tarde. |
| El diagnóstico de red (1.4) da `FALLA` en un puerto | Esa red lo bloquea (universidad, empresa, eduroam). Usa otra red, por ejemplo el punto de acceso del móvil. |
| DNIe Remote: «La información recuperada no es válida» al escanear el QR | El manual lo asocia a que PC y móvil no estén en la misma red (1.5). Compara sus IPv4, desactiva VPN y adaptadores virtuales, o vincula por USB. |
| DNIe Remote: `sign` se queda parado en «verificando PIN» | Mira si hay una ventana o una petición en el móvil esperando el PIN, y qué dice `PROTECTED_AUTHENTICATION_PATH` en `notary info` (1.5). Ctrl+C cuenta como un intento de PIN. |
| DNIe Remote: el emparejamiento por Wi-Fi tarda más de 10 s | Probable cortafuegos (1.5): mira la regla de DNIeRemote y el tipo de red, o vincula por USB. |
| `respuesta OCSP caducada` | El reloj del equipo está desajustado. |
| `INVALID ... caducado` | El certificado del DNIe ha caducado: renuévalo en un PAD. |
| La ventana de confirmación de OpenSC no aparece | Mira si quedó detrás de otra ventana; sin aceptarla no se firma. |

**Si necesitas ayuda,** copia la salida completa del comando (no el PIN: no aparece en ninguna salida). Antes de pegarla en un chat o enviarla, **tapa tu nombre y número de DNI**, que salen en `info` y `verify`.
