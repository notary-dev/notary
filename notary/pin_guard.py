"""Contador local de PIN incorrectos para no bloquear el DNIe.

El DNIe permite 3 PIN incorrectos seguidos antes de bloquearse. Con OpenSC no hay
forma de preguntar a la tarjeta cuántos quedan: el driver del DNIe no soporta esa
consulta (``SC_PIN_CMD_GET_INFO``) y la tarjeta solo informa tras un PIN erróneo,
así que el flag ``CKF_USER_PIN_FINAL_TRY`` no es fiable. Este módulo lleva la
cuenta por su lado: tras ``MAX_FAILED_BEFORE_REFUSAL`` fallos seguidos se niega a
pedir otro PIN y deja a la tarjeta con un intento de margen.

Solo se guarda un contador por tarjeta (identificada por el hash de su número de
serie), nunca el PIN. Limitación: solo cuenta los intentos hechos con ``notary``;
los de otros programas no los ve. Un PIN correcto, o el comando ``pin-guard``,
lo reinician.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import PyKCS11

from notary.pkcs11_utils import find_pkcs11_module

MAX_FAILED_BEFORE_REFUSAL = 2
CARD_MAX_TRIES = 3


def default_state_file() -> Path:
    """Fichero de estado: ``NOTARY_STATE_DIR`` si existe, o el directorio de datos del usuario."""
    override = os.environ.get("NOTARY_STATE_DIR")
    if override:
        base = Path(override)
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "notary"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))) / "notary"
    return base / "pin_guard.json"


def token_key(serial: str) -> str:
    """Identificador de tarjeta: hash del número de serie, para no guardarlo en claro."""
    return hashlib.sha256(serial.strip().encode("utf-8")).hexdigest()[:16]


class PinGuard:
    """Cuenta los PIN incorrectos por tarjeta y decide si se puede pedir otro."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path else default_state_file()

    def _load(self) -> Dict[str, dict]:
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise RuntimeError(
                f"no se puede leer el contador de PIN ({self._path}): {error}. "
                "Por seguridad no se pide el PIN; si sabes cuántos intentos quedan, "
                "usa 'notary pin-guard --set N' para reconstruirlo."
            ) from error
        if not isinstance(data, dict):
            raise RuntimeError(f"el contador de PIN ({self._path}) tiene un formato inesperado")
        return data

    def _save(self, data: Dict[str, dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def failed_attempts(self, serial: str) -> int:
        """PIN incorrectos registrados para esta tarjeta desde el último acierto."""
        entry = self._load().get(token_key(serial), {})
        return int(entry.get("failed", 0))

    def check_allowed(self, serial: str) -> None:
        """Lanza ``RuntimeError`` si pedir otro PIN pondría en riesgo el bloqueo."""
        failed = self.failed_attempts(serial)
        if failed >= MAX_FAILED_BEFORE_REFUSAL:
            remaining = max(CARD_MAX_TRIES - failed, 0)
            raise RuntimeError(
                f"Se han registrado {failed} PIN incorrectos seguidos con este DNIe: "
                f"te quedan como mucho {remaining} intento(s) antes de bloquearlo. "
                "notary no pide el PIN para no arriesgar el bloqueo. Comprueba el PIN "
                "en un Punto de Actualización del DNIe (PAD). Si ya lo has cambiado o "
                "sabes que el contador está completo, ejecuta 'notary pin-guard --reset'."
            )

    def set_failed(self, serial: str, failed: int) -> None:
        data = self._load()
        data[token_key(serial)] = {
            "failed": max(int(failed), 0),
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self._save(data)

    def record_failure(self, serial: str) -> int:
        failed = self.failed_attempts(serial) + 1
        self.set_failed(serial, failed)
        return failed

    def record_success(self, serial: str) -> None:
        if self.failed_attempts(serial) != 0:
            self.set_failed(serial, 0)


def run_pin_guard(
    reset: bool = False,
    set_failed: Optional[int] = None,
    module: Optional[str] = None,
) -> int:
    """Muestra, fija (``--set N``) o reinicia (``--reset``) el contador de la tarjeta conectada.

    Solo lee el número de serie del token: no abre sesión ni pide el PIN.
    """
    if reset and set_failed is not None:
        print("[!] --reset y --set son incompatibles.", file=sys.stderr)
        return 2
    if set_failed is not None and not 0 <= set_failed <= CARD_MAX_TRIES:
        print(f"[!] --set debe estar entre 0 y {CARD_MAX_TRIES}.", file=sys.stderr)
        return 2
    try:
        p11 = PyKCS11.PyKCS11Lib()
        p11.load(find_pkcs11_module(module))
        slots = p11.getSlotList(tokenPresent=True)
        if not slots:
            print("[!] No se ha detectado ningún DNIe.", file=sys.stderr)
            return 1
        serial = str(p11.getTokenInfo(slots[0]).serialNumber).strip()
        guard = PinGuard()
        if reset:
            guard.set_failed(serial, 0)
        elif set_failed is not None:
            guard.set_failed(serial, set_failed)
        failed = guard.failed_attempts(serial)
    except (OSError, RuntimeError, PyKCS11.PyKCS11Error) as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1

    print(f"Fallos de PIN registrados por notary para este DNIe: {failed} de {CARD_MAX_TRIES}")
    if failed >= MAX_FAILED_BEFORE_REFUSAL:
        print("notary se niega a pedir el PIN hasta que lo compruebes en un PAD y reinicies el contador.")
    else:
        print(f"notary se niega a pedir el PIN a partir de {MAX_FAILED_BEFORE_REFUSAL} fallos seguidos.")
    print("Aviso: solo cuenta los intentos hechos con notary, no los de otros programas.")
    return 0
