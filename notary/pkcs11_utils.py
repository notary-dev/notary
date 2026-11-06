"""PKCS#11 utility functions for detecting modules, slots, tokens, and flags."""

import os
from typing import List, Optional, Tuple
import PyKCS11
from PyKCS11.LowLevel import (
    CKF_TOKEN_INITIALIZED,
    CKF_USER_PIN_INITIALIZED,
    CKF_USER_PIN_LOCKED,
    CKF_USER_PIN_FINAL_TRY,
    CKF_LOGIN_REQUIRED,
    CKF_PROTECTED_AUTHENTICATION_PATH,
)

# Known default PKCS#11 library paths across operating systems
DEFAULT_PKCS11_PATHS = [
    # Windows: OpenSC (Standard USB smart card reader)
    r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
    # Windows: Oficial DNIe FNMT/Policia (Physical USB smart card reader)
    r"C:\Windows\System32\UsrPkcs11.dll",
    r"C:\Program Files\DNIe\UsrPkcs11.dll",
    r"C:\Program Files (x86)\DNIe\UsrPkcs11.dll",
    # Windows: DNIe Remote (CNP - FNMT, mobile phone via NFC)
    r"C:\Windows\System32\DNIeRemotePKCS11.dll",
    # Linux: OpenSC
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    # macOS: OpenSC (Homebrew; the assignment lists lib/, Homebrew installs in lib/pkcs11/)
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
    "/usr/local/lib/pkcs11/opensc-pkcs11.so",
    "/Library/OpenSC/lib/pkcs11/opensc-pkcs11.so",
    "/Library/OpenSC/lib/opensc-pkcs11.so",
]


def find_pkcs11_module(custom_path: Optional[str] = None) -> str:
    """Find a usable PKCS#11 module path, or return the provided custom path.

    If custom_path is provided, verifies that it exists.
    Otherwise, checks known paths and selects the first available module that
    reports a present token. If none does, raises FileNotFoundError instead of
    selecting a module that cannot currently see a token.
    """
    if custom_path:
        if not os.path.exists(custom_path):
            raise FileNotFoundError(
                f"No se ha encontrado un módulo PKCS#11 en la ruta indicada: {custom_path}"
            )
        return custom_path

    existing_modules = [p for p in DEFAULT_PKCS11_PATHS if os.path.exists(p)]
    if not existing_modules:
        raise FileNotFoundError(
            "No se han encontrado módulos PKCS#11 en las rutas habituales.\n"
            "Instala OpenSC o DNIe Remote, o indica la ruta del módulo con --module <ruta>."
        )

    # Si solo hay un módulo instalado en el sistema, devolverlo directamente para
    # no cargar/descargar dos veces la DLL ni abrir/cerrar el pipe de DNIe Remote.
    if len(existing_modules) == 1:
        return existing_modules[0]

    # Prefer the module that currently has a token inserted
    for module_path in existing_modules:
        try:
            p11 = PyKCS11.PyKCS11Lib()
            p11.load(module_path)
            slots = p11.getSlotList(tokenPresent=True)
            if slots:
                return module_path
        except Exception:
            continue

    raise FileNotFoundError(
        "Se han encontrado módulos PKCS#11, pero ninguno detecta un token presente.\n"
        "Conecta el DNIe o inicia DNIe Remote y vuelve a intentarlo. Si el módulo "
        "está instalado en otra ruta, indícala con --module <ruta>."
    )


def get_token_flags_description(flags: int) -> List[Tuple[str, bool]]:
    """Return a list of (flag_name, is_set) for relevant security and status flags."""
    flag_checks = [
        ("TOKEN_INITIALIZED", bool(flags & CKF_TOKEN_INITIALIZED)),
        ("USER_PIN_INITIALIZED", bool(flags & CKF_USER_PIN_INITIALIZED)),
        ("LOGIN_REQUIRED", bool(flags & CKF_LOGIN_REQUIRED)),
        ("USER_PIN_LOCKED", bool(flags & CKF_USER_PIN_LOCKED)),
        ("USER_PIN_FINAL_TRY", bool(flags & CKF_USER_PIN_FINAL_TRY)),
        ("PROTECTED_AUTHENTICATION_PATH", bool(flags & CKF_PROTECTED_AUTHENTICATION_PATH)),
    ]
    return flag_checks
