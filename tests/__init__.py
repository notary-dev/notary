"""Las pruebas nunca deben tocar una tarjeta real ni el contador de PIN del usuario."""

import atexit
import os
import shutil
import tempfile

import PyKCS11

# Contador de PIN en un directorio temporal, no en el del usuario.
_STATE_DIR = tempfile.mkdtemp(prefix="notary-tests-")
os.environ["NOTARY_STATE_DIR"] = _STATE_DIR
atexit.register(shutil.rmtree, _STATE_DIR, ignore_errors=True)


def _no_real_pkcs11_module(self, *args, **kwargs):
    raise RuntimeError("los tests no pueden cargar un módulo PKCS#11 real (DNIe o DNIe Remote conectado)")


# Con OpenSC instalado y un DNIe conectado, un test que firmara sin --key abriría la tarjeta
# real y esperaría el PIN. Los tests que necesitan una tarjeta usan una sesión simulada
# (``p11_factory``), que no pasa por esta carga.
PyKCS11.PyKCS11Lib.load = _no_real_pkcs11_module
