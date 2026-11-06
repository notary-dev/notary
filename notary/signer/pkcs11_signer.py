"""Firmante PKCS#11 para el DNIe: selecciona CertFirmaDigital y protege el PIN."""

import getpass
from typing import Callable, Optional, Tuple

import PyKCS11
from asn1crypto import algos, x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from PyKCS11.LowLevel import (
    CKF_PROTECTED_AUTHENTICATION_PATH,
    CKF_USER_PIN_FINAL_TRY,
    CKF_USER_PIN_LOCKED,
)

from notary.info import _to_bytes, _to_str, get_key_usage_names
from notary.pin_guard import CARD_MAX_TRIES, PinGuard
from notary.pkcs11_utils import find_pkcs11_module
from notary.signer.base import Signer


def check_pin_security_flags(flags: int) -> None:
    """Aborta antes de pedir el PIN si el DNIe está bloqueado o en su último intento."""
    if flags & CKF_USER_PIN_LOCKED:
        raise RuntimeError(
            "El PIN del DNIe está bloqueado (CKF_USER_PIN_LOCKED). "
            "Acude a un Punto de Actualización del DNIe (PAD) para desbloquearlo."
        )
    if flags & CKF_USER_PIN_FINAL_TRY:
        raise RuntimeError(
            "Seguridad del PIN: CKF_USER_PIN_FINAL_TRY está activo (solo queda 1 intento "
            "antes de bloquear el DNIe). Se aborta la operación para proteger la tarjeta."
        )


def build_sha256_digest_info(digest: bytes) -> bytes:
    """Empaqueta un resumen SHA-256 de 32 bytes en una estructura DER DigestInfo (RFC 8017)."""
    if len(digest) != 32:
        raise ValueError("El resumen SHA-256 debe tener exactamente 32 bytes.")
    return algos.DigestInfo(
        {
            "digest_algorithm": {"algorithm": "sha256"},
            "digest": digest,
        }
    ).dump()


def _default_pin_prompt() -> str:
    """Solicita el PIN de forma oculta por terminal mediante getpass."""
    return getpass.getpass("Introduce el PIN del DNIe: ")


class PKCS11Signer(Signer):
    """Implementación de ``Signer`` que firma dentro del chip del DNIe vía PKCS#11."""

    def __init__(
        self,
        module_path: Optional[str] = None,
        pin_provider: Callable[[], str] = _default_pin_prompt,
        p11_factory: Callable[[], PyKCS11.PyKCS11Lib] = PyKCS11.PyKCS11Lib,
        guard: Optional[PinGuard] = None,
    ) -> None:
        self._module_path = find_pkcs11_module(module_path)
        self._pin_provider = pin_provider
        self._p11 = p11_factory()
        self._p11.load(self._module_path)
        self._session = None

        # Seguir exactamente la secuencia de notary info: getSlotList() + una única
        # llamada a getSlotInfo(slot) para inicializar la ranura sin reiniciar el pipe.
        present_slots = []
        all_slots = self._p11.getSlotList()
        for s in all_slots:
            if hasattr(self._p11, "getSlotInfo"):
                try:
                    slot_info = self._p11.getSlotInfo(s)
                    if bool(slot_info.flags & PyKCS11.CKF_TOKEN_PRESENT):
                        present_slots.append(s)
                except Exception:
                    pass
            else:
                present_slots.append(s)

        if not present_slots and not hasattr(self._p11, "getSlotInfo"):
            present_slots = self._p11.getSlotList(tokenPresent=True)

        if not present_slots:
            raise RuntimeError(
                "No se ha detectado ningún DNIe presente en el lector PKCS#11."
            )
        self._slot = present_slots[0]

        token_info = self._p11.getTokenInfo(self._slot)
        check_pin_security_flags(token_info.flags)
        # Con CKF_PROTECTED_AUTHENTICATION_PATH el PIN se escribe fuera de la aplicación
        # (teclado del lector, ventana del módulo o móvil) y C_Login debe recibir NULL.
        self._protected_path = bool(token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
        self._guard = guard if guard is not None else PinGuard()
        self._token_serial = str(token_info.serialNumber).strip()

        self._session = self._p11.openSession(self._slot)
        try:
            self._certificate, self._cert_id, self._cert_label = (
                self._load_signature_certificate(self._session)
            )
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        """Cierra la sesión PKCS#11 si sigue abierta."""
        if getattr(self, "_session", None) is not None:
            try:
                self._session.closeSession()
            except Exception:
                pass
            self._session = None

    def __del__(self) -> None:
        self.close()

    def _load_signature_certificate(
        self, session
    ) -> Tuple[asn1_x509.Certificate, bytes, str]:
        """Lee en sesión pública (sin PIN) el certificado de firma (CertFirmaDigital)."""
        cert_objects = session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
        )
        if not cert_objects:
            raise RuntimeError(
                "No se han encontrado certificados X.509 en el DNIe."
            )

        fallback_match: Optional[Tuple[asn1_x509.Certificate, bytes, str]] = None
        for obj in cert_objects:
            attrs = session.getAttributeValue(
                obj,
                [PyKCS11.CKA_VALUE, PyKCS11.CKA_LABEL, PyKCS11.CKA_ID],
            )
            cert_der = _to_bytes(attrs[0])
            label = _to_str(attrs[1]).strip() if attrs[1] else ""
            cert_id = _to_bytes(attrs[2]) if attrs[2] else b""
            cert = asn1_x509.Certificate.load(cert_der)

            usages = get_key_usage_names(cert)
            if "non_repudiation" in usages or "content_commitment" in usages:
                return cert, cert_id, label
            if fallback_match is None and "firma" in label.lower():
                fallback_match = (cert, cert_id, label)

        if fallback_match is not None:
            return fallback_match

        raise RuntimeError(
            "No se ha encontrado ningún certificado de firma (content_commitment / "
            "CertFirmaDigital) en el DNIe."
        )

    def _find_private_key(self, session):
        """Localiza el objeto de clave privada que corresponde al certificado de firma."""
        if self._cert_id:
            keys = session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_ID, list(self._cert_id)),
                ]
            )
            if keys:
                return keys[0]
            keys = session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_ID, self._cert_id),
                ]
            )
            if keys:
                return keys[0]

        all_keys = session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]
        )
        for key_obj in all_keys:
            try:
                attrs = session.getAttributeValue(
                    key_obj, [PyKCS11.CKA_ID, PyKCS11.CKA_LABEL]
                )
                key_id = _to_bytes(attrs[0]) if attrs[0] else b""
                key_label = _to_str(attrs[1]).strip() if attrs[1] else ""
                if self._cert_id and key_id == self._cert_id:
                    return key_obj
                if "firma" in key_label.lower():
                    return key_obj
            except Exception:
                continue

        if len(all_keys) == 1:
            return all_keys[0]

        raise RuntimeError(
            "No se ha encontrado la clave privada de firma (KprivFirmaDigital) en el DNIe."
        )

    def get_certificate(self) -> asn1_x509.Certificate:
        """Devuelve el certificado X.509 de firma del DNIe."""
        return self._certificate

    def sign_hash(self, digest: bytes) -> bytes:
        """Pide al DNIe que firme ``digest`` (SHA-256) con RSA PKCS#1 v1.5 sin reintentos."""
        digest_info = build_sha256_digest_info(digest)

        self._guard.check_allowed(self._token_serial)

        if self._protected_path:
            print(
                "[*] Este DNIe pide el PIN fuera del terminal (ventana del módulo, "
                "teclado del lector o móvil). Introdúcelo allí."
            )
            pin = None
        else:
            pin = self._pin_provider()
            if pin is not None:
                pin = pin.strip("\r\n")
            if not pin:
                raise RuntimeError(
                    "No se ha introducido ningún PIN. Operación cancelada sin tocar la tarjeta."
                )

        if self._session is None:
            self._session = self._p11.openSession(self._slot)
        session = self._session

        logged_in = False
        try:
            try:
                print("[*] Conectando con el DNIe y verificando PIN...")
                print(
                    "    Si se queda aquí parado, mira si hay una ventana (quizá detrás de otras) "
                    "o una petición en el móvil esperando el PIN.\n"
                    "    Cortar con Ctrl+C cuenta como un intento de PIN."
                )
                session.login(pin)
                logged_in = True
                self._guard.record_success(self._token_serial)
                print("[+] PIN aceptado por el DNIe.")
            except KeyboardInterrupt:
                # Si el PIN llegó a la tarjeta, ya descontó un intento: por seguridad se cuenta.
                failed = self._guard.record_failure(self._token_serial)
                print(
                    "\n[!] Verificación del PIN interrumpida. No se sabe si la tarjeta descontó "
                    f"un intento, así que se cuenta como gastado ({failed} de {CARD_MAX_TRIES}). "
                    "Si sabes que no, ajusta el contador con 'notary pin-guard --set N'."
                )
                raise
            except PyKCS11.PyKCS11Error as error:
                note = ""
                if error.value == PyKCS11.CKR_PIN_INCORRECT:
                    failed = self._guard.record_failure(self._token_serial)
                    note = (
                        f" Fallos seguidos registrados: {failed} de {CARD_MAX_TRIES}; "
                        "no pruebes más PIN antes de comprobarlo en un PAD."
                    )
                elif error.value == PyKCS11.CKR_PIN_LOCKED:
                    self._guard.set_failed(self._token_serial, CARD_MAX_TRIES)
                raise RuntimeError(
                    f"Fallo de autenticación o comunicación en el DNIe ({error}). "
                    "No se reintenta automáticamente para evitar bloquear la tarjeta." + note
                ) from error
            finally:
                pin = ""

            print("[*] Calculando firma en el chip del DNIe (KprivFirmaDigital)...")
            priv_key = self._find_private_key(session)
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
            raw_sig = session.sign(priv_key, list(digest_info), mechanism)
            signature = _to_bytes(raw_sig)
        finally:
            if logged_in:
                try:
                    session.logout()
                except Exception:
                    pass
            self.close()

        # Comprobar que la firma devuelta por la tarjeta verifica con el certificado público.
        crypto_cert = crypto_x509.load_der_x509_certificate(self._certificate.dump())
        crypto_cert.public_key().verify(
            signature,
            digest,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256()),
        )
        print("[+] Firma generada por el chip del DNIe y comprobada con su certificado.")
        return signature
