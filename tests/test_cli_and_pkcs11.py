"""Pruebas de la CLI, de las rutas PKCS#11, de roles y del firmante PKCS11Signer."""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from unittest import mock

import PyKCS11
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

from notary import cli, pkcs11_utils
from notary.cades.builder import build_cades_bes
from notary.info import identify_certificate_role
from notary.signer.pkcs11_signer import PKCS11Signer, build_sha256_digest_info
from notary.verify import verify_cms_core
from tools import generate_test_ca


class _FakeCert:
    def __init__(self, usages):
        self.key_usage_value = type("KU", (), {"native": set(usages)})()


class CliTests(unittest.TestCase):
    def test_missing_files_fail(self):
        for argv in (["sign", "no_existe.txt"], ["verify", "no_existe.csig"]):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertNotEqual(cli.main(argv), 0)

    def test_no_command_prints_help_and_fails(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main([]), 1)


class Pkcs11Tests(unittest.TestCase):
    def test_macos_homebrew_path_has_pkcs11_subdir(self):
        self.assertIn(
            "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
            pkcs11_utils.DEFAULT_PKCS11_PATHS,
        )

    def test_missing_custom_module_raises(self):
        with self.assertRaises(FileNotFoundError):
            pkcs11_utils.find_pkcs11_module("/no/existe.so")

    def test_flags_are_decoded(self):
        flags = dict(
            pkcs11_utils.get_token_flags_description(
                pkcs11_utils.CKF_USER_PIN_FINAL_TRY
            )
        )
        self.assertTrue(flags["USER_PIN_FINAL_TRY"])
        self.assertFalse(flags["USER_PIN_LOCKED"])


class RoleTests(unittest.TestCase):
    def test_non_repudiation_is_signature_cert(self):
        self.assertIn(
            "CertFirmaDigital",
            identify_certificate_role(_FakeCert({"non_repudiation"}), "x"),
        )

    def test_digital_signature_is_authentication_cert(self):
        self.assertIn(
            "CertAutenticacion",
            identify_certificate_role(_FakeCert({"digital_signature"}), "x"),
        )

    def test_role_does_not_depend_on_label(self):
        role = identify_certificate_role(
            _FakeCert({"non_repudiation"}), "CertAutenticacion"
        )
        self.assertIn("CertFirmaDigital", role)


class _SimulatedSession:
    """Sesión PKCS#11 simulada que emula C_Sign con CKM_RSA_PKCS (bloque DigestInfo)."""

    def __init__(self, certs, keys_by_id, login_error=None):
        self._certs = certs
        self._keys_by_id = keys_by_id
        self._login_error = login_error
        self.logged_in = False
        self.login_attempts = 0
        self.last_signed_payload = None

    def findObjects(self, template):
        t_dict = dict(template)
        obj_class = t_dict.get(PyKCS11.CKA_CLASS)
        if obj_class == PyKCS11.CKO_CERTIFICATE:
            return list(range(len(self._certs)))
        if obj_class == PyKCS11.CKO_PRIVATE_KEY:
            target_id = t_dict.get(PyKCS11.CKA_ID)
            if target_id is not None:
                target_bytes = bytes(target_id)
                return [
                    k_id for k_id in self._keys_by_id if k_id == target_bytes
                ]
            return list(self._keys_by_id.keys())
        return []

    def getAttributeValue(self, obj, attr_types):
        if isinstance(obj, int):
            cert_der, label, cert_id = self._certs[obj]
            mapping = {
                PyKCS11.CKA_VALUE: list(cert_der),
                PyKCS11.CKA_LABEL: label,
                PyKCS11.CKA_ID: list(cert_id),
            }
            return [mapping[a] for a in attr_types]
        mapping = {
            PyKCS11.CKA_ID: list(obj),
            PyKCS11.CKA_LABEL: "KprivFirmaDigital",
        }
        return [mapping[a] for a in attr_types]

    def login(self, pin):
        self.login_attempts += 1
        if self._login_error is not None:
            raise self._login_error
        self.logged_in = True

    def sign(self, key_obj, data, mechanism):
        if not self.logged_in:
            raise RuntimeError("C_Sign invocado sin login previo")
        raw_bytes = bytes(data)
        self.last_signed_payload = raw_bytes
        # CKM_RSA_PKCS recibe el DigestInfo de 51 bytes; extraemos los últimos 32 bytes
        # (el hash SHA-256) tras comprobar el prefijo DER DigestInfo de SHA-256.
        expected_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
        if not raw_bytes.startswith(expected_prefix) or len(raw_bytes) != 51:
            raise ValueError("CKM_RSA_PKCS esperaba un DigestInfo SHA-256 de 51 bytes")
        digest = raw_bytes[19:]
        priv_key = self._keys_by_id[key_obj]
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

        sig = priv_key.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
        return list(sig)

    def logout(self):
        self.logged_in = False

    def closeSession(self):
        pass


class _SimulatedP11Lib:
    def __init__(self, flags, session):
        self.flags = flags
        self.session = session

    def load(self, path):
        pass

    def getSlotList(self, tokenPresent=False):
        return [1]

    def getTokenInfo(self, slot):
        return type("TokenInfo", (), {"flags": self.flags, "serialNumber": "TOKEN-DE-PRUEBA"})()

    def openSession(self, slot):
        return self.session


class Pkcs11SignerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        old = sys.argv
        sys.argv = ["generate_test_ca", "--output-dir", str(cls.dir)]
        try:
            with redirect_stdout(io.StringIO()):
                generate_test_ca.main()
        finally:
            sys.argv = old

        now = datetime.now(timezone.utc)
        ca_key = serialization.load_pem_private_key(
            (cls.dir / "test_ca.key").read_bytes(), password=None
        )
        ca_cert = crypto_x509.load_pem_x509_certificate(
            (cls.dir / "test_ca.crt").read_bytes()
        )
        cls.sign_key = serialization.load_pem_private_key(
            (cls.dir / "signer.key").read_bytes(), password=None
        )
        cls.sign_cert_der = crypto_x509.load_pem_x509_certificate(
            (cls.dir / "signer.crt").read_bytes()
        ).public_bytes(serialization.Encoding.DER)

        # Crear también un certificado de autenticación (solo digital_signature, sin content_commitment).
        auth_key = serialization.load_pem_private_key(
            (cls.dir / "short_signer.key").read_bytes(), password=None
        )
        auth_subject = crypto_x509.Name(
            [
                crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Notary Test"),
                crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Notary Auth Only"),
            ]
        )
        auth_cert = (
            crypto_x509.CertificateBuilder()
            .subject_name(auth_subject)
            .issuer_name(ca_cert.subject)
            .public_key(auth_key.public_key())
            .serial_number(crypto_x509.random_serial_number())
            .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
            .not_valid_after((now + timedelta(days=10)).replace(tzinfo=None))
            .add_extension(
                crypto_x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                crypto_x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cls.auth_cert_der = auth_cert.public_bytes(serialization.Encoding.DER)
        cls.auth_key = auth_key

        cls.fake_module = cls.dir / "fake_pkcs11.dll"
        cls.fake_module.write_bytes(b"fake")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _make_session(self, login_error=None):
        # Ponemos primero el certificado de autenticación para comprobar que elige el de firma.
        certs = [
            (self.auth_cert_der, "CertAutenticacion", b"id-auth"),
            (self.sign_cert_der, "CertFirmaDigital", b"id-firma"),
        ]
        keys = {
            b"id-auth": self.auth_key,
            b"id-firma": self.sign_key,
        }
        return _SimulatedSession(certs, keys, login_error=login_error)

    def test_selects_signature_certificate_and_signs_digest_info(self):
        session = self._make_session()
        p11 = _SimulatedP11Lib(flags=0, session=session)
        pin_calls = []

        signer = PKCS11Signer(
            module_path=str(self.fake_module),
            pin_provider=lambda: (pin_calls.append(1) or "1234"),
            p11_factory=lambda: p11,
        )
        # Antes de firmar no se ha pedido el PIN.
        self.assertEqual(len(pin_calls), 0)
        self.assertIn(
            "Notary Test Signer", signer.get_certificate().subject.human_friendly
        )

        doc = b"Documento firmado con PKCS#11"
        der = build_cades_bes(doc, signer, detached=False)
        self.assertEqual(len(pin_calls), 1)
        self.assertEqual(len(session.last_signed_payload), 51)

        # La firma generada con PKCS11Signer pasa la verificación CMS y matemática.
        res = verify_cms_core(der)
        self.assertEqual(res.document, doc)

    def test_refuses_when_pin_final_try_flag_is_active(self):
        session = self._make_session()
        p11 = _SimulatedP11Lib(
            flags=pkcs11_utils.CKF_USER_PIN_FINAL_TRY, session=session
        )
        pin_calls = []

        with self.assertRaisesRegex(RuntimeError, "CKF_USER_PIN_FINAL_TRY"):
            PKCS11Signer(
                module_path=str(self.fake_module),
                pin_provider=lambda: (pin_calls.append(1) or "1234"),
                p11_factory=lambda: p11,
            )
        self.assertEqual(len(pin_calls), 0)
        self.assertEqual(session.login_attempts, 0)

    def test_refuses_when_pin_locked_flag_is_active(self):
        session = self._make_session()
        p11 = _SimulatedP11Lib(
            flags=pkcs11_utils.CKF_USER_PIN_LOCKED, session=session
        )
        with self.assertRaisesRegex(RuntimeError, "CKF_USER_PIN_LOCKED"):
            PKCS11Signer(
                module_path=str(self.fake_module),
                pin_provider=lambda: "1234",
                p11_factory=lambda: p11,
            )

    def test_login_failure_does_not_retry_pin(self):
        session = self._make_session(login_error=PyKCS11.PyKCS11Error(0xA0))
        p11 = _SimulatedP11Lib(flags=0, session=session)
        pin_calls = []

        signer = PKCS11Signer(
            module_path=str(self.fake_module),
            pin_provider=lambda: (pin_calls.append(1) or "0000"),
            p11_factory=lambda: p11,
        )
        with self.assertRaisesRegex(RuntimeError, "No se reintenta"):
            signer.sign_hash(sha256(b"datos").digest())

        self.assertEqual(len(pin_calls), 1)
        self.assertEqual(session.login_attempts, 1)

    def test_digest_info_requires_32_byte_sha256(self):
        with self.assertRaises(ValueError):
            build_sha256_digest_info(b"corto")


if __name__ == "__main__":
    unittest.main()
