"""Pruebas del comando verify (Fases 1A, 1B, 1C y 1D: CMS, cadenas, TSA, tiempo y OCSP)."""

import random
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from unittest import mock

import requests
from asn1crypto import cms, tsp, x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from notary import cli
from notary.cades.builder import _signing_certificate_v2_attribute, build_cades_bes
from notary.ocsp import extract_ocsp_urls
from notary.signer.software_signer import SoftwareSigner
from notary.verify import VerificationInvalid, verify_cms_core
from tools import forger, generate_test_ca

_TEST_OCSP_URL = "http://ocsp.notary.test/responder"


def _create_tsa_credentials(output_dir: Path, now: datetime, ca_key, ca_cert):
    """Crea un certificado de TSA con ExtendedKeyUsage timeStamping bajo la CA de prueba."""
    tsa_key = ca_key
    tsa_subject = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Notary Test TSA"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Notary Test TSA Responder"),
        ]
    )
    tsa_cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(tsa_subject)
        .issuer_name(ca_cert.subject)
        .public_key(tsa_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=365)).replace(tzinfo=None))
        .add_extension(crypto_x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
        .add_extension(
            crypto_x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    asn1_tsa_cert = asn1_x509.Certificate.load(
        tsa_cert.public_bytes(serialization.Encoding.DER)
    )
    return tsa_key, asn1_tsa_cert


def _create_aia_signer_credentials(output_dir: Path, now: datetime, ca_key, ca_cert, signer_key):
    """Crea un certificado de firmante que incluye una URL OCSP en su extensión AIA."""
    subject = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Notary Test"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Notary OCSP Signer"),
        ]
    )
    aia_ext = crypto_x509.AuthorityInformationAccess(
        [
            crypto_x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                crypto_x509.UniformResourceIdentifier(_TEST_OCSP_URL),
            )
        ]
    )
    cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(signer_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=30)).replace(tzinfo=None))
        .add_extension(crypto_x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            crypto_x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
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
        .add_extension(aia_ext, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = output_dir / "aia_signer.crt"
    generate_test_ca.save_certificate(cert, cert_path)
    return cert, cert_path


def _build_ocsp_response(
    signer_cert: crypto_x509.Certificate,
    issuer_cert: crypto_x509.Certificate,
    responder_cert: crypto_x509.Certificate,
    responder_key,
    now: datetime,
    cert_status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD,
    revocation_time: datetime = None,
    include_certs: list = None,
) -> bytes:
    """Construye una respuesta OCSP DER firmada."""
    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=signer_cert,
        issuer=issuer_cert,
        algorithm=hashes.SHA1(),
        cert_status=cert_status,
        this_update=now - timedelta(minutes=5),
        next_update=now + timedelta(hours=1),
        revocation_time=revocation_time,
        revocation_reason=crypto_x509.ReasonFlags.key_compromise
        if cert_status == ocsp.OCSPCertStatus.REVOKED
        else None,
    ).responder_id(ocsp.OCSPResponderEncoding.NAME, responder_cert)
    if include_certs:
        builder = builder.certificates(include_certs)
    response = builder.sign(responder_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


def _build_signed_timestamp_token(
    imprint: bytes,
    gen_time: datetime,
    tsa_key,
    asn1_tsa_cert: asn1_x509.Certificate,
) -> bytes:
    """Construye un TimeStampToken CMS SignedData firmado criptográficamente por la TSA."""
    tst_info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": imprint,
            },
            "serial_number": 42,
            "gen_time": gen_time,
            "nonce": 123456789,
        }
    )
    tst_der = tst_info.dump()
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
            cms.CMSAttribute(
                {"type": "message_digest", "values": [sha256(tst_der).digest()]}
            ),
            _signing_certificate_v2_attribute(asn1_tsa_cert),
        ]
    )
    attrs_der = signed_attrs.dump(force=True)
    sig = tsa_key.sign(attrs_der, padding.PKCS1v15(), hashes.SHA256())

    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": {
                "issuer_and_serial_number": {
                    "issuer": asn1_tsa_cert.issuer,
                    "serial_number": asn1_tsa_cert.serial_number,
                }
            },
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": signed_attrs,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": sig,
        }
    )
    token = cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {
                    "content_type": "tst_info",
                    "content": tst_info,
                },
                "certificates": [
                    cms.CertificateChoices(name="certificate", value=asn1_tsa_cert)
                ],
                "signer_infos": [signer_info],
            },
        }
    )
    return token.dump()


class _FakeHttpReply:
    def __init__(self, content: bytes):
        self.content = content

    def raise_for_status(self):
        return None


class VerifyTests(unittest.TestCase):
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
        cls.now = datetime.now(timezone.utc).replace(microsecond=0)
        cls.signer = SoftwareSigner(str(cls.dir / "signer.key"), str(cls.dir / "signer.crt"))
        cls.short_signer = SoftwareSigner(
            str(cls.dir / "short_signer.key"), str(cls.dir / "short_signer.crt")
        )
        cls.signer_ca_path = str(cls.dir / "test_ca.crt")

        cls.ca_key = serialization.load_pem_private_key(
            (cls.dir / "test_ca.key").read_bytes(), password=None
        )
        cls.ca_cert = crypto_x509.load_pem_x509_certificate(
            (cls.dir / "test_ca.crt").read_bytes()
        )
        cls.signer_key = serialization.load_pem_private_key(
            (cls.dir / "signer.key").read_bytes(), password=None
        )

        cls.tsa_key, cls.tsa_cert = _create_tsa_credentials(
            cls.dir, cls.now, cls.ca_key, cls.ca_cert
        )
        cls.aia_crypto_cert, aia_cert_path = _create_aia_signer_credentials(
            cls.dir, cls.now, cls.ca_key, cls.ca_cert, cls.signer_key
        )
        cls.aia_signer = SoftwareSigner(str(cls.dir / "signer.key"), str(aia_cert_path))

        cls.doc = cls.dir / "contrato.txt"
        cls.doc_bytes = b"Contrato de prueba para Notary"
        cls.doc.write_bytes(cls.doc_bytes)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run_verify(self, *argv):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["verify", *argv])
        return code, out.getvalue(), err.getvalue()

    def _timestamper_at(self, gen_time: datetime):
        def _stamp(signature: bytes) -> bytes:
            return _build_signed_timestamp_token(
                sha256(signature).digest(),
                gen_time,
                self.tsa_key,
                self.tsa_cert,
            )
        return _stamp

    def test_valid_cades_t_detached_is_valid(self):
        proof_path = self.dir / "valid_t.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.signer,
                detached=True,
                timestamper=self._timestamper_at(self.now),
            )
        )
        code, stdout, _ = self._run_verify(
            str(proof_path),
            "--content",
            str(self.doc),
            "--trust",
            self.signer_ca_path,
        )
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("VEREDICTO: VALID — firmado por Notary Test Signer", stdout)
        self.assertIn("Notary Test TSA Responder", stdout)

    def test_without_trust_returns_indeterminate(self):
        proof_path = self.dir / "no_trust.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.signer,
                detached=True,
                timestamper=self._timestamper_at(self.now),
            )
        )
        code, stdout, _ = self._run_verify(str(proof_path), "--content", str(self.doc))
        self.assertEqual(code, 2)
        self.assertIn("VEREDICTO: INDETERMINATE", stdout)

    def test_untrusted_tsa_returns_indeterminate(self):
        # Firmar el sello con una CA de TSA desconocida que no se pasa en --trust.
        untrusted_ca_name = crypto_x509.Name(
            [
                crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted TSA Org"),
                crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted TSA Root CA"),
            ]
        )
        untrusted_tsa_ca = (
            crypto_x509.CertificateBuilder()
            .subject_name(untrusted_ca_name)
            .issuer_name(untrusted_ca_name)
            .public_key(self.signer_key.public_key())
            .serial_number(crypto_x509.random_serial_number())
            .not_valid_before((self.now - timedelta(days=1)).replace(tzinfo=None))
            .not_valid_after((self.now + timedelta(days=30)).replace(tzinfo=None))
            .add_extension(crypto_x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.signer_key, hashes.SHA256())
        )
        _, untrusted_tsa_cert = _create_tsa_credentials(
            self.dir, self.now, self.signer_key, untrusted_tsa_ca
        )

        def _untrusted_stamp(signature: bytes) -> bytes:
            return _build_signed_timestamp_token(
                sha256(signature).digest(),
                self.now,
                self.signer_key,
                untrusted_tsa_cert,
            )

        proof_path = self.dir / "untrusted_tsa.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.signer,
                detached=True,
                timestamper=_untrusted_stamp,
            )
        )
        code, stdout, _ = self._run_verify(
            str(proof_path),
            "--content",
            str(self.doc),
            "--trust",
            self.signer_ca_path,
        )
        self.assertEqual(code, 2, msg=stdout)
        self.assertIn("VEREDICTO: INDETERMINATE", stdout)
        self.assertIn("TSA", stdout)

    def test_timestamp_over_document_instead_of_signature_is_invalid(self):
        def _bad_stamp(_signature: bytes) -> bytes:
            return _build_signed_timestamp_token(
                sha256(self.doc_bytes).digest(),
                self.now,
                self.tsa_key,
                self.tsa_cert,
            )

        proof_path = self.dir / "stamp_over_doc.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes, self.signer, detached=True, timestamper=_bad_stamp
            )
        )
        code, stdout, _ = self._run_verify(
            str(proof_path),
            "--content",
            str(self.doc),
            "--trust",
            self.signer_ca_path,
        )
        self.assertEqual(code, 1)
        self.assertIn("VEREDICTO: INVALID", stdout)
        self.assertIn("sobre el documento en lugar de sobre el valor de firma", stdout)

    def test_timestamp_from_another_signature_is_invalid(self):
        def _other_stamp(_signature: bytes) -> bytes:
            return _build_signed_timestamp_token(
                sha256(b"otra firma distinta").digest(),
                self.now,
                self.tsa_key,
                self.tsa_cert,
            )

        proof_path = self.dir / "stamp_other.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes, self.signer, detached=True, timestamper=_other_stamp
            )
        )
        code, stdout, _ = self._run_verify(
            str(proof_path),
            "--content",
            str(self.doc),
            "--trust",
            self.signer_ca_path,
        )
        self.assertEqual(code, 1)
        self.assertIn("VEREDICTO: INVALID", stdout)
        self.assertIn("imprint del sello de tiempo no coincide", stdout)

    def test_short_lived_certificate_valid_at_tsa_time_and_invalid_after_expiration(self):
        proof_valid = self.dir / "short_valid_at_tsa.csig"
        proof_valid.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.short_signer,
                detached=True,
                timestamper=self._timestamper_at(self.now + timedelta(seconds=30)),
            )
        )
        code, stdout, _ = self._run_verify(
            str(proof_valid),
            "--content",
            str(self.doc),
            "--trust",
            self.signer_ca_path,
        )
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("VEREDICTO: VALID", stdout)

        future_iso = (self.now + timedelta(minutes=10)).isoformat()
        code_late, stdout_late, _ = self._run_verify(
            str(proof_valid),
            "--content",
            str(self.doc),
            "--trust",
            self.signer_ca_path,
            "--at",
            future_iso,
        )
        self.assertEqual(code_late, 1)
        self.assertIn("VEREDICTO: INVALID", stdout_late)
        self.assertIn("caducado", stdout_late)

        proof_expired_at_tsa = self.dir / "short_expired_at_tsa.csig"
        proof_expired_at_tsa.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.short_signer,
                detached=True,
                timestamper=self._timestamper_at(self.now + timedelta(minutes=10)),
            )
        )
        code_exp, stdout_exp, _ = self._run_verify(
            str(proof_expired_at_tsa),
            "--content",
            str(self.doc),
            "--trust",
            self.signer_ca_path,
        )
        self.assertEqual(code_exp, 1)
        self.assertIn("VEREDICTO: INVALID", stdout_exp)
        self.assertIn("caducado", stdout_exp)

    def test_cades_bes_without_timestamp_warns_that_time_is_only_a_claim(self):
        proof_bes = self.dir / "bes_no_ts.csig"
        proof_bes.write_bytes(build_cades_bes(self.doc_bytes, self.signer, detached=True))

        code, stdout, _ = self._run_verify(
            str(proof_bes),
            "--content",
            str(self.doc),
            "--trust",
            self.signer_ca_path,
        )
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("NO INCLUIDO (CAdES-BES: solo hora declarada)", stdout)
        self.assertIn("sin sello de tiempo; la única fecha que contiene es una declaración", stdout)

    def test_extracts_ocsp_url_from_certificate_aia_and_validates_good_status(self):
        urls = extract_ocsp_urls(self.aia_signer.get_certificate())
        self.assertEqual(urls, [_TEST_OCSP_URL])

        proof_path = self.dir / "ocsp_good.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.aia_signer,
                detached=True,
                timestamper=self._timestamper_at(self.now),
            )
        )
        ocsp_der = _build_ocsp_response(
            self.aia_crypto_cert,
            self.ca_cert,
            self.ca_cert,
            self.ca_key,
            self.now,
            cert_status=ocsp.OCSPCertStatus.GOOD,
        )
        called_urls = []

        def _fake_post(url, data, **kwargs):
            called_urls.append(url)
            return _FakeHttpReply(ocsp_der)

        with mock.patch("notary.ocsp.requests.post", side_effect=_fake_post):
            code, stdout, _ = self._run_verify(
                str(proof_path),
                "--content",
                str(self.doc),
                "--trust",
                self.signer_ca_path,
            )
        self.assertEqual(code, 0, msg=stdout)
        self.assertEqual(called_urls, [_TEST_OCSP_URL])
        self.assertIn(f"[8] Estado de revocación (OCSP) ... GOOD ({_TEST_OCSP_URL}) (OK)", stdout)
        self.assertIn("VEREDICTO: VALID", stdout)

    def test_ocsp_revoked_certificate_returns_invalid(self):
        proof_path = self.dir / "ocsp_revoked.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.aia_signer,
                detached=True,
                timestamper=self._timestamper_at(self.now),
            )
        )
        ocsp_der = _build_ocsp_response(
            self.aia_crypto_cert,
            self.ca_cert,
            self.ca_cert,
            self.ca_key,
            self.now,
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=self.now - timedelta(hours=2),
        )
        with mock.patch(
            "notary.ocsp.requests.post", return_value=_FakeHttpReply(ocsp_der)
        ):
            code, stdout, _ = self._run_verify(
                str(proof_path),
                "--content",
                str(self.doc),
                "--trust",
                self.signer_ca_path,
            )
        self.assertEqual(code, 1)
        self.assertIn("VEREDICTO: INVALID", stdout)
        self.assertIn("REVOCADO", stdout)

    def test_ocsp_revoked_after_tsa_time_stays_valid(self):
        proof_path = self.dir / "ocsp_revoked_later.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.aia_signer,
                detached=True,
                timestamper=self._timestamper_at(self.now),
            )
        )
        ocsp_der = _build_ocsp_response(
            self.aia_crypto_cert,
            self.ca_cert,
            self.ca_cert,
            self.ca_key,
            self.now,
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=self.now + timedelta(hours=2),
        )
        with mock.patch(
            "notary.ocsp.requests.post", return_value=_FakeHttpReply(ocsp_der)
        ):
            code, stdout, _ = self._run_verify(
                str(proof_path),
                "--content",
                str(self.doc),
                "--trust",
                self.signer_ca_path,
            )
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("VEREDICTO: VALID", stdout)

    def test_mutated_proofs_never_raise(self):
        good = build_cades_bes(
            self.doc_bytes,
            self.aia_signer,
            detached=True,
            timestamper=self._timestamper_at(self.now),
        )
        fuzz_path = self.dir / "fuzz.csig"
        rng = random.Random(1)
        for _ in range(150):
            mutated = bytearray(good)
            for _ in range(rng.randint(1, 4)):
                position = rng.randrange(len(mutated))
                mutated[position] = rng.randrange(256)
            fuzz_path.write_bytes(bytes(mutated))
            with mock.patch(
                "notary.ocsp.requests.post",
                side_effect=requests.ConnectionError("sin red"),
            ):
                code, stdout, _ = self._run_verify(
                    str(fuzz_path),
                    "--content",
                    str(self.doc),
                    "--trust",
                    self.signer_ca_path,
                )
            self.assertIn(code, (0, 1, 2))
            self.assertIn("VEREDICTO:", stdout)

    def _ocsp_der_at(self, this_update_shift, nonce=None, next_update_shift=timedelta(hours=1)):
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=self.aia_crypto_cert,
            issuer=self.ca_cert,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=self.now + this_update_shift,
            next_update=self.now + next_update_shift,
            revocation_time=None,
            revocation_reason=None,
        ).responder_id(ocsp.OCSPResponderEncoding.NAME, self.ca_cert)
        if nonce is not None:
            builder = builder.add_extension(crypto_x509.OCSPNonce(nonce), critical=False)
        return builder.sign(self.ca_key, hashes.SHA256()).public_bytes(
            serialization.Encoding.DER
        )

    def _check_ocsp(self, response_der, **kwargs):
        from notary.ocsp import verify_ocsp_response

        issuer = asn1_x509.Certificate.load(
            self.ca_cert.public_bytes(serialization.Encoding.DER)
        )
        return verify_ocsp_response(
            response_der, self.aia_signer.get_certificate(), issuer, **kwargs
        )

    def test_ocsp_stale_response_is_indeterminate(self):
        from notary.ocsp import OcspIndeterminate

        old = self._ocsp_der_at(-timedelta(days=30), next_update_shift=-timedelta(days=29))
        with self.assertRaises(OcspIndeterminate):
            self._check_ocsp(old, now=self.now)
        # Sin exigir frescura (respuesta incrustada en la firma) la misma respuesta es válida.
        self.assertEqual(self._check_ocsp(old), "GOOD")

    def test_ocsp_response_from_the_future_is_indeterminate(self):
        from notary.ocsp import OcspIndeterminate

        future = self._ocsp_der_at(timedelta(days=2), next_update_shift=timedelta(days=3))
        with self.assertRaises(OcspIndeterminate):
            self._check_ocsp(future, now=self.now)

    def test_ocsp_nonce_mismatch_is_invalid_and_match_is_good(self):
        from notary.ocsp import OcspInvalid

        replayed = self._ocsp_der_at(-timedelta(minutes=1), nonce=b"viejo-viejo-1234")
        with self.assertRaises(OcspInvalid):
            self._check_ocsp(replayed, expected_nonce=b"nuevo-nuevo-5678", now=self.now)
        fresh = self._ocsp_der_at(-timedelta(minutes=1), nonce=b"nuevo-nuevo-5678")
        self.assertEqual(
            self._check_ocsp(fresh, expected_nonce=b"nuevo-nuevo-5678", now=self.now),
            "GOOD",
        )

    def _ltv_proof(self, name, ocsp_der, tsa_time=None):
        from notary.cades.ltv import build_ltv_attributes

        ca_asn1 = asn1_x509.Certificate.load(
            self.ca_cert.public_bytes(serialization.Encoding.DER)
        )
        proof_path = self.dir / name
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.aia_signer,
                detached=True,
                timestamper=self._timestamper_at(tsa_time or self.now),
                ltv_provider=lambda: build_ltv_attributes([ca_asn1], ocsp_der),
            )
        )
        return proof_path

    def _verify_offline(self, proof_path):
        with mock.patch(
            "notary.ocsp.requests.post",
            side_effect=requests.ConnectionError("sin red"),
        ):
            return self._run_verify(
                str(proof_path), "--content", str(self.doc), "--trust", self.signer_ca_path
            )

    def test_ltv_proof_verifies_offline(self):
        good = _build_ocsp_response(
            self.aia_crypto_cert, self.ca_cert, self.ca_cert, self.ca_key, self.now
        )
        code, stdout, _ = self._verify_offline(self._ltv_proof("ltv_ok.csig", good))
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("LTV", stdout)
        self.assertIn("VEREDICTO: VALID", stdout)

    def test_proof_without_ltv_is_indeterminate_when_ocsp_is_down(self):
        proof_path = self.dir / "no_ltv.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.aia_signer,
                detached=True,
                timestamper=self._timestamper_at(self.now),
            )
        )
        code, stdout, _ = self._verify_offline(proof_path)
        self.assertEqual(code, 2, msg=stdout)

    def test_ltv_ocsp_older_than_timestamp_is_indeterminate(self):
        good = _build_ocsp_response(
            self.aia_crypto_cert, self.ca_cert, self.ca_cert, self.ca_key, self.now
        )
        proof_path = self._ltv_proof(
            "ltv_old.csig", good, tsa_time=self.now + timedelta(hours=1)
        )
        code, stdout, _ = self._verify_offline(proof_path)
        self.assertEqual(code, 2, msg=stdout)
        self.assertIn("anterior al sello", stdout)

    def test_ltv_embedded_revoked_response_is_invalid(self):
        revoked = _build_ocsp_response(
            self.aia_crypto_cert,
            self.ca_cert,
            self.ca_cert,
            self.ca_key,
            self.now,
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=self.now - timedelta(hours=2),
        )
        code, stdout, _ = self._verify_offline(self._ltv_proof("ltv_rev.csig", revoked))
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("REVOCADO", stdout)

    def test_ltv_embedded_response_for_another_cert_is_not_used(self):
        other = _build_ocsp_response(
            self.signer.get_certificate() and crypto_x509.load_der_x509_certificate(
                self.signer.get_certificate().dump()
            ),
            self.ca_cert,
            self.ca_cert,
            self.ca_key,
            self.now,
        )
        code, stdout, _ = self._verify_offline(self._ltv_proof("ltv_other.csig", other))
        self.assertEqual(code, 2, msg=stdout)

    def test_sign_ltv_embeds_chain_and_ocsp(self):
        good = _build_ocsp_response(
            self.aia_crypto_cert, self.ca_cert, self.ca_cert, self.ca_key, self.now
        )
        out = self.dir / "cli_ltv.csig"
        fake_token = lambda signature, urls, **kw: (  # noqa: E731
            self._timestamper_at(self.now)(signature),
            urls[0],
        )
        with mock.patch("notary.sign.request_timestamp", fake_token), mock.patch(
            "notary.ocsp.requests.post", return_value=_FakeHttpReply(good)
        ):
            code, stdout, _ = self._run_cli(
                "sign", str(self.doc), "--key", str(self.dir / "signer.key"),
                "--cert", str(self.dir / "aia_signer.crt"), "--ltv",
                "--chain", self.signer_ca_path, "--tsa", "http://tsa-simulada",
                "--out", str(out),
            )
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("CAdES-LT", stdout)
        code, stdout, _ = self._verify_offline(out)
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("LTV", stdout)

    def _run_cli(self, *argv):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_sign_ltv_fails_without_evidence(self):
        out = self.dir / "cli_ltv_fail.csig"
        with mock.patch(
            "notary.ocsp.requests.post", side_effect=requests.ConnectionError("sin red")
        ), mock.patch(
            "notary.sign.request_timestamp",
            lambda signature, urls, **kw: (self._timestamper_at(self.now)(signature), urls[0]),
        ):
            code, _, stderr = self._run_cli(
                "sign", str(self.doc), "--key", str(self.dir / "signer.key"),
                "--cert", str(self.dir / "aia_signer.crt"), "--ltv",
                "--chain", self.signer_ca_path, "--tsa", "http://tsa-simulada",
                "--out", str(out),
            )
        self.assertEqual(code, 1)
        self.assertFalse(out.exists())
        self.assertIn("OCSP", stderr)

    def _two_signer_proof(self, name, second_signer, second_tsa_time):
        from notary.cades.builder import add_parallel_signature

        first = build_cades_bes(
            self.doc_bytes, self.signer, detached=True, timestamper=self._timestamper_at(self.now)
        )
        proof_path = self.dir / name
        proof_path.write_bytes(
            add_parallel_signature(
                first,
                self.doc_bytes,
                second_signer,
                timestamper=self._timestamper_at(second_tsa_time),
            )
        )
        return proof_path

    def test_two_parallel_signers_are_all_reported(self):
        proof_path = self._two_signer_proof("two_ok.csig", self.short_signer, self.now)
        code, stdout, _ = self._run_verify(
            str(proof_path), "--content", str(self.doc), "--trust", self.signer_ca_path
        )
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("=== Firmante 1 de 2 ===", stdout)
        self.assertIn("=== Firmante 2 de 2 ===", stdout)
        self.assertIn("VEREDICTO FINAL: VALID (2 firmantes", stdout)

    def test_one_bad_signer_makes_the_global_verdict_invalid(self):
        # El segundo certificado dura 2 minutos y el sello es 10 minutos posterior.
        proof_path = self._two_signer_proof(
            "two_bad.csig", self.short_signer, self.now + timedelta(minutes=10)
        )
        code, stdout, _ = self._run_verify(
            str(proof_path), "--content", str(self.doc), "--trust", self.signer_ca_path
        )
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("VEREDICTO FINAL: INVALID", stdout)
        # DER ordena los SignerInfo por sus bytes: no se puede suponer cuál es el primero.
        summary = stdout.splitlines()[-1]
        self.assertIn("INVALID", summary.split("firmantes;")[1])
        self.assertIn(": VALID", summary)

    def test_cosign_cli_adds_a_second_signature(self):
        fake_token = lambda signature, urls, **kw: (  # noqa: E731
            self._timestamper_at(self.now)(signature),
            urls[0],
        )
        base = self.dir / "cosign_base.csig"
        out = self.dir / "cosign_out.csig"
        with mock.patch("notary.sign.request_timestamp", fake_token):
            code, stdout, _ = self._run_cli(
                "sign", str(self.doc), "--key", str(self.dir / "signer.key"),
                "--cert", str(self.dir / "signer.crt"), "--tsa", "http://tsa-simulada",
                "--out", str(base),
            )
            self.assertEqual(code, 0, msg=stdout)
            code, stdout, _ = self._run_cli(
                "cosign", str(base), str(self.doc), "--key", str(self.dir / "short_signer.key"),
                "--cert", str(self.dir / "short_signer.crt"), "--tsa", "http://tsa-simulada",
                "--out", str(out),
            )
        self.assertEqual(code, 0, msg=stdout)
        code, stdout, _ = self._run_verify(
            str(out), "--content", str(self.doc), "--trust", self.signer_ca_path
        )
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("VEREDICTO FINAL: VALID (2 firmantes", stdout)
        # La prueba original no se modifica.
        code, stdout, _ = self._run_verify(
            str(base), "--content", str(self.doc), "--trust", self.signer_ca_path
        )
        self.assertEqual(code, 0, msg=stdout)

    def test_cosign_rejects_the_same_certificate_twice(self):
        base = self.dir / "dup_base.csig"
        base.write_bytes(
            build_cades_bes(
                self.doc_bytes, self.signer, detached=True,
                timestamper=self._timestamper_at(self.now),
            )
        )
        from notary.cades.builder import add_parallel_signature

        with self.assertRaises(ValueError):
            add_parallel_signature(base.read_bytes(), self.doc_bytes, self.signer)

    def test_ca_without_key_cert_sign_cannot_issue(self):
        from notary.verify import _is_ca_certificate

        key = self.ca_key
        name = self.ca_cert.subject

        def _ca_with_usage(key_cert_sign):
            cert = (
                crypto_x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(crypto_x509.random_serial_number())
                .not_valid_before(datetime(2020, 1, 1))
                .not_valid_after(datetime(2040, 1, 1))
                .add_extension(crypto_x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    crypto_x509.KeyUsage(
                        digital_signature=True, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=key_cert_sign,
                        crl_sign=key_cert_sign, encipher_only=None, decipher_only=None,
                    ),
                    critical=True,
                )
                .sign(key, hashes.SHA256())
            )
            return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))

        self.assertTrue(_is_ca_certificate(_ca_with_usage(True)))
        self.assertFalse(_is_ca_certificate(_ca_with_usage(False)))
        self.assertFalse(_is_ca_certificate(self.signer.get_certificate()))

    def test_ocsp_unreachable_returns_indeterminate(self):
        proof_path = self.dir / "ocsp_down.csig"
        proof_path.write_bytes(
            build_cades_bes(
                self.doc_bytes,
                self.aia_signer,
                detached=True,
                timestamper=self._timestamper_at(self.now),
            )
        )
        with mock.patch(
            "notary.ocsp.requests.post",
            side_effect=requests.ConnectionError("servidor OCSP inalcanzable"),
        ):
            code, stdout, _ = self._run_verify(
                str(proof_path),
                "--content",
                str(self.doc),
                "--trust",
                self.signer_ca_path,
            )
        self.assertEqual(code, 2)
        self.assertIn("VEREDICTO: INDETERMINATE", stdout)
        self.assertIn("OCSP", stdout)

    def test_valid_attached_core_works_without_content_flag(self):
        proof_path = self.dir / "valid_attached.csig"
        proof_path.write_bytes(build_cades_bes(self.doc_bytes, self.signer, detached=False))

        result = verify_cms_core(proof_path.read_bytes(), content_path=None)
        self.assertFalse(result.detached)
        self.assertEqual(result.document, self.doc_bytes)

    def test_attached_rejects_mismatched_external_content(self):
        proof_bytes = build_cades_bes(self.doc_bytes, self.signer, detached=False)
        other_doc = self.dir / "otro.txt"
        other_doc.write_bytes(b"Contenido distinto")

        with self.assertRaisesRegex(VerificationInvalid, "no coincide con el contenido adjunto"):
            verify_cms_core(proof_bytes, content_path=str(other_doc))

    def test_detached_without_content_is_invalid(self):
        proof_path = self.dir / "det_no_content.csig"
        proof_path.write_bytes(build_cades_bes(self.doc_bytes, self.signer, detached=True))

        code, stdout, _ = self._run_verify(str(proof_path))
        self.assertEqual(code, 1)
        self.assertIn("VEREDICTO: INVALID", stdout)
        self.assertIn("--content", stdout)

    def test_modified_document_fails_message_digest(self):
        proof_path = self.dir / "det_tampered_doc.csig"
        proof_path.write_bytes(build_cades_bes(self.doc_bytes, self.signer, detached=True))
        tampered_doc = self.dir / "contrato_alterado.txt"
        tampered_doc.write_bytes(self.doc_bytes + b"!")

        code, stdout, _ = self._run_verify(str(proof_path), "--content", str(tampered_doc))
        self.assertEqual(code, 1)
        self.assertIn("VEREDICTO: INVALID", stdout)
        self.assertIn("messageDigest", stdout)

    def test_truncated_or_garbage_file_never_crashes_and_returns_invalid(self):
        valid_der = build_cades_bes(self.doc_bytes, self.signer, detached=True)
        for name, bad_bytes in (
            ("vacio.csig", b""),
            ("basura.csig", b"esto no es ASN.1 DER"),
            ("truncado.csig", valid_der[:-30]),
        ):
            bad_path = self.dir / name
            bad_path.write_bytes(bad_bytes)
            code, stdout, _ = self._run_verify(str(bad_path), "--content", str(self.doc))
            self.assertEqual(code, 1, msg=f"Falló para {name}")
            self.assertIn("VEREDICTO: INVALID", stdout)

    def test_corrupted_signature_value_is_invalid(self):
        valid_der = build_cades_bes(self.doc_bytes, self.signer, detached=True)
        content_info = cms.ContentInfo.load(valid_der)
        signed_data = content_info["content"]
        signer_info = signed_data["signer_infos"][0]
        sig = bytearray(signer_info["signature"].native)
        sig[0] ^= 0xFF
        signer_info["signature"] = bytes(sig)
        forged_der = content_info.dump(force=True)

        with self.assertRaisesRegex(VerificationInvalid, "firma matemática"):
            verify_cms_core(forged_der, content_path=str(self.doc))

    def test_tampered_signed_attribute_signing_time_is_invalid(self):
        valid_der = build_cades_bes(self.doc_bytes, self.signer, detached=True)
        content_info = cms.ContentInfo.load(valid_der)
        signer_info = content_info["content"]["signer_infos"][0]
        for attr in signer_info["signed_attrs"]:
            if attr["type"].native == "signing_time":
                attr["values"] = [
                    cms.Time(
                        name="utc_time",
                        value=datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                    )
                ]
        forged_der = content_info.dump(force=True)

        with self.assertRaisesRegex(VerificationInvalid, "firma matemática"):
            verify_cms_core(forged_der, content_path=str(self.doc))

    def test_signing_certificate_v2_mismatch_is_invalid(self):
        valid_der = build_cades_bes(self.doc_bytes, self.signer, detached=True)
        content_info = cms.ContentInfo.load(valid_der)
        signed_data = content_info["content"]
        other_cert = self.short_signer.get_certificate()
        signed_data["certificates"] = [
            cms.CertificateChoices(name="certificate", value=other_cert)
        ]
        signed_data["signer_infos"][0]["sid"] = {
            "issuer_and_serial_number": {
                "issuer": other_cert.issuer,
                "serial_number": other_cert.serial_number,
            }
        }
        forged_der = content_info.dump(force=True)

        with self.assertRaisesRegex(VerificationInvalid, "signingCertificateV2"):
            verify_cms_core(forged_der, content_path=str(self.doc))

    def test_forger_pair_exchange_set_matches_answer_key(self):
        base_proof = build_cades_bes(
            self.doc_bytes,
            self.signer,
            detached=True,
            timestamper=self._timestamper_at(self.now),
        )
        exchange_dir = self.dir / "pair_exchange"
        entries = forger.generate_pair_exchange_set(
            exchange_dir, base_proof, self.doc_bytes
        )
        self.assertEqual(len(entries), 6)
        self.assertTrue((exchange_dir / "answer_key.md").exists())
        self.assertTrue((exchange_dir / "answer_key.json").exists())

        expected_codes = {"VALID": 0, "INVALID": 1, "INDETERMINATE": 2}
        for item in entries:
            argv = [str(exchange_dir / item["proof"]), "--trust", self.signer_ca_path]
            if item["content"]:
                argv.extend(["--content", str(exchange_dir / item["content"])])
            code, stdout, _ = self._run_verify(*argv)
            expected = item["expected_verdict"]
            self.assertEqual(
                code,
                expected_codes[expected],
                msg=f"Fallo en {item['id']} ({item['flaw']}):\n{stdout}",
            )
            self.assertIn(f"VEREDICTO: {expected}", stdout)


if __name__ == "__main__":
    unittest.main()
