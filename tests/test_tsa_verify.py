"""Pruebas de la verificación del sello de tiempo: TSA reales grabadas, ataques y revocación."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from unittest import mock

from asn1crypto import cms, tsp, x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from notary import cli
from notary.cades.builder import build_cades_bes
from notary.ocsp import OcspIndeterminate, OcspInvalid
from notary.signer.software_signer import SoftwareSigner
from notary.verify import (
    TimestampCheckResult,
    VerificationInvalid,
    check_tsa_revocation,
)
from tests.test_verify import _build_signed_timestamp_token
from tools import generate_test_ca

_FIXTURES = Path(__file__).parent / "fixtures" / "tsa_real"
_DOC = b"doc\n"


def _quiet_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue()


class RealTsaTokensTests(unittest.TestCase):
    """Sellos pedidos a TSA reales el 2026-10-30 (firmante de prueba, sin claves privadas).

    La validez de los certificados se evalúa a la hora del sello, así que estas
    firmas siguen verificándose aunque caduquen los certificados de las TSA.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.doc = Path(cls._tmp.name) / "doc.txt"
        cls.doc.write_bytes(_DOC)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _verify(self, name):
        with mock.patch("notary.verify.check_ocsp_revocation", return_value=None):
            return _quiet_cli(
                "verify", str(_FIXTURES / f"{name}.csig"), "--content", str(self.doc),
                "--trust", str(_FIXTURES / "test_ca.crt"), str(_FIXTURES / "roots.pem"),
            )

    def test_real_tokens_are_valid(self):
        # apple y accv: raíz firmada con SHA-1; apple además firma el token con SHA-1.
        for name in ("freetsa", "digicert", "sectigo", "globalsign", "apple", "certum", "accv"):
            with self.subTest(tsa=name):
                code, stdout = self._verify(name)
                self.assertEqual(code, 0, msg=stdout)
                self.assertIn("Cadena de la TSA", stdout)

    def test_real_token_without_its_root_is_indeterminate_not_invalid(self):
        with mock.patch("notary.verify.check_ocsp_revocation", return_value=None):
            code, stdout = _quiet_cli(
                "verify", str(_FIXTURES / "apple.csig"), "--content", str(self.doc),
                "--trust", str(_FIXTURES / "test_ca.crt"),
            )
        self.assertEqual(code, 2, msg=stdout)
        self.assertIn("INDETERMINATE", stdout)


def _tsa_cert(ca_key, ca_cert, now, eku=True, eku_critical=True, ocsp_url=None,
              not_before=None, not_after=None):
    builder = (
        crypto_x509.CertificateBuilder()
        .subject_name(crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, "TSA de prueba")]))
        .issuer_name(ca_cert.subject)
        .public_key(ca_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before((not_before or now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((not_after or now + timedelta(days=30)).replace(tzinfo=None))
        .add_extension(crypto_x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if eku:
        builder = builder.add_extension(
            crypto_x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=eku_critical,
        )
    if ocsp_url:
        builder = builder.add_extension(
            crypto_x509.AuthorityInformationAccess([
                crypto_x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    crypto_x509.UniformResourceIdentifier(ocsp_url),
                )
            ]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


class TsaAttackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        import sys
        old = sys.argv
        sys.argv = ["generate_test_ca", "--output-dir", str(cls.dir)]
        try:
            with redirect_stdout(io.StringIO()):
                generate_test_ca.main()
        finally:
            sys.argv = old
        cls.now = datetime.now(timezone.utc).replace(microsecond=0)
        cls.signer = SoftwareSigner(str(cls.dir / "signer.key"), str(cls.dir / "signer.crt"))
        cls.ca_key = serialization.load_pem_private_key(
            (cls.dir / "test_ca.key").read_bytes(), password=None
        )
        cls.ca_cert = crypto_x509.load_pem_x509_certificate((cls.dir / "test_ca.crt").read_bytes())
        cls.ca_path = str(cls.dir / "test_ca.crt")
        cls.doc_bytes = b"contrato"
        cls.doc = cls.dir / "contrato.txt"
        cls.doc.write_bytes(cls.doc_bytes)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _proof(self, name, tsa_cert, mutate=None):
        def stamp(signature):
            token = _build_signed_timestamp_token(
                sha256(signature).digest(), self.now, self.ca_key, tsa_cert
            )
            return mutate(token) if mutate else token

        path = self.dir / f"{name}.csig"
        path.write_bytes(build_cades_bes(self.doc_bytes, self.signer, detached=True, timestamper=stamp))
        return path

    def _verify(self, path):
        return _quiet_cli("verify", str(path), "--content", str(self.doc), "--trust", self.ca_path)

    def test_baseline_is_valid(self):
        path = self._proof("base", _tsa_cert(self.ca_key, self.ca_cert, self.now))
        code, stdout = self._verify(path)
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("Revocación de la TSA ........ No aplica", stdout)

    def test_tampered_tsa_signature_is_invalid(self):
        def flip(token_der):
            signature = cms.ContentInfo.load(token_der)["content"]["signer_infos"][0]["signature"].native
            bad = signature[:-1] + bytes([signature[-1] ^ 1])
            return token_der.replace(signature, bad)

        path = self._proof("badsig", _tsa_cert(self.ca_key, self.ca_cert, self.now), flip)
        code, stdout = self._verify(path)
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("firma matemática no es válida", stdout)

    def test_tstinfo_changed_after_signing_is_invalid(self):
        # El nonce (123456789 = 0x075BCD15) se cambia sin volver a firmar.
        path = self._proof(
            "badinfo", _tsa_cert(self.ca_key, self.ca_cert, self.now),
            lambda token: token.replace(b"\x07\x5b\xcd\x15", b"\x07\x5b\xcd\x16"),
        )
        code, stdout = self._verify(path)
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("messageDigest del token TSA no coincide", stdout)

    def test_tsa_certificate_without_time_stamping_eku_is_invalid(self):
        path = self._proof("noeku", _tsa_cert(self.ca_key, self.ca_cert, self.now, eku=False))
        code, stdout = self._verify(path)
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("ExtendedKeyUsage timeStamping", stdout)

    def test_tsa_certificate_with_non_critical_eku_is_invalid(self):
        path = self._proof(
            "noncrit", _tsa_cert(self.ca_key, self.ca_cert, self.now, eku_critical=False)
        )
        code, stdout = self._verify(path)
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("no es crítico", stdout)

    def test_token_without_signing_certificate_attribute_is_invalid(self):
        from asn1crypto import cms as _cms

        def no_ess(_cert):
            stamp = _cms.Time(name="utc_time", value=self.now)
            return _cms.CMSAttribute({"type": "signing_time", "values": [stamp]})

        with mock.patch("tests.test_verify._signing_certificate_v2_attribute", no_ess):
            path = self._proof("noess", _tsa_cert(self.ca_key, self.ca_cert, self.now))
        code, stdout = self._verify(path)
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("signingCertificateV2", stdout)

    def test_revoked_tsa_certificate_is_invalid_end_to_end(self):
        cert = _tsa_cert(self.ca_key, self.ca_cert, self.now, ocsp_url="http://ocsp.tsa.test")
        path = self._proof("revoked", cert)
        with mock.patch(
            "notary.verify.check_ocsp_revocation",
            side_effect=OcspInvalid("el certificado está REVOCADO (fecha de revocación: ayer)"),
        ):
            code, stdout = self._verify(path)
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("certificado de la TSA", stdout)

    def test_good_tsa_certificate_is_reported(self):
        cert = _tsa_cert(self.ca_key, self.ca_cert, self.now, ocsp_url="http://ocsp.tsa.test")
        path = self._proof("good", cert)
        with mock.patch("notary.verify.check_ocsp_revocation", return_value=("GOOD", "http://ocsp.tsa.test")):
            code, stdout = self._verify(path)
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("Revocación de la TSA ........ GOOD (http://ocsp.tsa.test)", stdout)


class TsaRevocationUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = datetime.now(timezone.utc).replace(microsecond=0)
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, "CA")])
        ca = (
            crypto_x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(cls.key.public_key()).serial_number(1)
            .not_valid_before((cls.now - timedelta(days=2)).replace(tzinfo=None))
            .not_valid_after((cls.now + timedelta(days=2)).replace(tzinfo=None))
            .add_extension(crypto_x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.key, hashes.SHA256())
        )
        cls.ca = ca
        cls.ca_asn1 = asn1_x509.Certificate.load(ca.public_bytes(serialization.Encoding.DER))

    def _result(self, chain):
        return TimestampCheckResult(
            gen_time=self.now, tsa_cert=chain[0], tsa_chain=chain, imprint_algorithm="sha256"
        )

    def _chain(self, **kwargs):
        return [_tsa_cert(self.key, self.ca, self.now, ocsp_url="http://o.test", **kwargs), self.ca_asn1]

    def test_queries_ocsp_with_the_timestamp_time(self):
        with mock.patch("notary.verify.check_ocsp_revocation", return_value=("GOOD", "u")) as ocsp:
            self.assertEqual(check_tsa_revocation(self._result(self._chain())), ("GOOD", "u"))
        self.assertEqual(ocsp.call_args.kwargs["eval_time"], self.now)

    def test_revoked_raises_invalid(self):
        with mock.patch("notary.verify.check_ocsp_revocation", side_effect=OcspInvalid("REVOCADO")):
            with self.assertRaises(VerificationInvalid):
                check_tsa_revocation(self._result(self._chain()))

    def test_unreachable_or_unknown_ocsp_does_not_change_the_verdict(self):
        for error in (OcspIndeterminate("UNKNOWN"), ValueError("respuesta ilegible")):
            with self.subTest(error=error):
                with mock.patch("notary.verify.check_ocsp_revocation", side_effect=error):
                    status, url = check_tsa_revocation(self._result(self._chain()))
                self.assertTrue(status.startswith("NO CONSULTABLE"))

    def test_expired_tsa_certificate_does_not_change_the_verdict(self):
        chain = [
            _tsa_cert(self.key, self.ca, self.now, ocsp_url="http://o.test",
                      not_before=self.now - timedelta(days=2), not_after=self.now - timedelta(days=1)),
            self.ca_asn1,
        ]
        with mock.patch("notary.verify.check_ocsp_revocation", side_effect=OcspIndeterminate("sin respuesta")):
            status, _ = check_tsa_revocation(self._result(chain))
        self.assertTrue(status.startswith("NO CONSULTABLE"))

    def test_nothing_to_query_returns_none(self):
        with mock.patch("notary.verify.check_ocsp_revocation", return_value=None):
            self.assertIsNone(check_tsa_revocation(self._result(self._chain())))
        self.assertIsNone(check_tsa_revocation(self._result([self.ca_asn1])))


if __name__ == "__main__":
    unittest.main()
