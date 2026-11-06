"""Pruebas de PAdES: firma de PDF como actualización incremental y su verificación."""

import io
import random
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from pypdf import PdfWriter

from notary import cli
from notary.cades.builder import build_cades_bes
from notary.pades import extract_pdf_signatures, sign_pdf
from notary.signer.software_signer import SoftwareSigner
from tests.test_verify import _build_signed_timestamp_token, _create_tsa_credentials
from tools import generate_test_ca

FIXTURES = Path(__file__).parent / "fixtures"


def _plain_pdf(pages: int = 2) -> bytes:
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(300, 300)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


class PadesTests(unittest.TestCase):
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
        cls.other_signer = SoftwareSigner(
            str(cls.dir / "short_signer.key"), str(cls.dir / "short_signer.crt")
        )
        cls.trust = str(cls.dir / "test_ca.crt")
        ca_key = serialization.load_pem_private_key(
            (cls.dir / "test_ca.key").read_bytes(), password=None
        )
        ca_cert = crypto_x509.load_pem_x509_certificate((cls.dir / "test_ca.crt").read_bytes())
        cls.tsa_key, cls.tsa_cert = _create_tsa_credentials(cls.dir, cls.now, ca_key, ca_cert)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _stamp(self, signature: bytes) -> bytes:
        return _build_signed_timestamp_token(
            sha256(signature).digest(), self.now, self.tsa_key, self.tsa_cert
        )

    def _sign(self, pdf: bytes, signer=None, timestamped: bool = True, reserve=None) -> bytes:
        signer = signer or self.signer

        def build_cms(signed_bytes: bytes) -> bytes:
            return build_cades_bes(
                signed_bytes,
                signer,
                detached=True,
                timestamper=self._stamp if timestamped else None,
                include_signing_time=False,
            )

        if reserve is None:
            return sign_pdf(pdf, build_cms)
        return sign_pdf(pdf, build_cms, reserve=reserve)

    def _verify(self, pdf: bytes, name: str = "v.pdf"):
        path = self.dir / name
        path.write_bytes(pdf)
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = cli.main(["verify", str(path), "--trust", self.trust])
        return code, out.getvalue()

    def test_signed_pdf_is_valid_and_reports_tsa_time(self):
        signed = self._sign(_plain_pdf())
        code, stdout = self._verify(signed)
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("PAdES (ETSI.CAdES.detached)", stdout)
        self.assertIn("Sello de tiempo (TSA)", stdout)
        self.assertIn("VEREDICTO: VALID", stdout)

    def test_signing_is_an_incremental_update_of_the_original_bytes(self):
        original = _plain_pdf()
        signed = self._sign(original)
        self.assertTrue(signed.startswith(original))
        self.assertGreater(len(signed), len(original))

    def test_byte_range_covers_everything_but_the_contents_value(self):
        signed = self._sign(_plain_pdf())
        (signature,) = extract_pdf_signatures(signed)
        self.assertEqual(signature.range_end, len(signed))
        self.assertLess(len(signature.signed_content), len(signed))

    def test_cross_reference_stream_pdf_is_signed(self):
        signed = self._sign((FIXTURES / "pdf_xref_stream.pdf").read_bytes())
        code, stdout = self._verify(signed)
        self.assertEqual(code, 0, msg=stdout)

    def test_pdf_with_catalog_and_pages_in_object_streams_is_signed(self):
        signed = self._sign((FIXTURES / "pdf_object_streams.pdf").read_bytes())
        code, stdout = self._verify(signed)
        self.assertEqual(code, 0, msg=stdout)

    def test_two_signers_are_both_reported_and_the_first_stays_valid(self):
        first = self._sign(_plain_pdf())
        second = self._sign(first, signer=self.other_signer)
        code, stdout = self._verify(second, "two.pdf")
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("=== Firma PDF 1 de 2 ===", stdout)
        self.assertIn("=== Firma PDF 2 de 2 ===", stdout)
        self.assertIn("VEREDICTO FINAL: VALID (2 firmas PDF", stdout)

    def test_modifying_signed_content_is_invalid(self):
        signed = bytearray(self._sign(_plain_pdf()))
        position = signed.index(b"/MediaBox") + 12
        signed[position] = ord("9")
        code, stdout = self._verify(bytes(signed), "tampered.pdf")
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("INVALID", stdout)

    def test_content_appended_after_the_signature_is_invalid(self):
        signed = self._sign(_plain_pdf()) + b"\n%contenido anadido despues de firmar\n"
        code, stdout = self._verify(signed, "appended.pdf")
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("añadidos después", stdout)

    def test_byte_range_not_pointing_at_contents_is_invalid(self):
        signed = self._sign(_plain_pdf())
        marker = b"/ByteRange [0 "
        position = signed.index(marker) + len(marker)
        original_number = signed[position : position + 10]
        shifted = b"%10d" % (int(original_number) - 50)
        forged = signed[:position] + shifted + signed[position + 10 :]
        code, stdout = self._verify(forged, "range.pdf")
        self.assertEqual(code, 1, msg=stdout)
        self.assertIn("INVALID", stdout)

    def test_pdf_without_signature_is_invalid(self):
        code, stdout = self._verify(_plain_pdf(), "unsigned.pdf")
        self.assertEqual(code, 1)
        self.assertIn("no contiene ninguna firma", stdout)

    def test_untrusted_pdf_signature_is_indeterminate(self):
        signed = self._sign(_plain_pdf())
        path = self.dir / "other_trust.pdf"
        path.write_bytes(signed)
        other_trust = self.dir / "short_signer.crt"  # certificado hoja: no es ancla de la cadena
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = cli.main(["verify", str(path), "--trust", str(other_trust)])
        self.assertEqual(code, 2, msg=out.getvalue())

    def test_mutated_signed_pdfs_never_raise(self):
        signed = self._sign(_plain_pdf())
        rng = random.Random(7)
        for _ in range(120):
            mutated = bytearray(signed)
            for _ in range(rng.randint(1, 4)):
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)
            code, stdout = self._verify(bytes(mutated), "fuzz.pdf")
            self.assertIn(code, (0, 1, 2))
            self.assertIn("VEREDICTO", stdout)

    def test_signature_larger_than_the_reservation_is_rejected(self):
        with self.assertRaises(ValueError):
            self._sign(_plain_pdf(), reserve=100)

    def test_non_pdf_and_encrypted_pdf_are_rejected(self):
        with self.assertRaises(ValueError):
            self._sign(b"esto no es un pdf")
        writer = PdfWriter()
        writer.add_blank_page(100, 100)
        writer.encrypt("secreto")
        buffer = io.BytesIO()
        writer.write(buffer)
        with self.assertRaises(ValueError):
            self._sign(buffer.getvalue())


class PadesCommandTests(unittest.TestCase):
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
        cls.pdf = cls.dir / "doc.pdf"
        cls.pdf.write_bytes(_plain_pdf())
        cls.key = str(cls.dir / "signer.key")
        cls.cert = str(cls.dir / "signer.crt")
        cls.trust = str(cls.dir / "test_ca.crt")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_sign_pades_writes_signed_pdf_next_to_the_original(self):
        code, stdout, _ = self._run(
            "sign", str(self.pdf), "--format", "pades", "--key", self.key, "--cert", self.cert,
            "--no-timestamp",
        )
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("PAdES-B-B", stdout)
        self.assertIn("/M", stdout)
        signed = self.dir / "doc.signed.pdf"
        self.assertTrue(signed.exists())
        self.assertEqual(self.pdf.read_bytes(), signed.read_bytes()[: len(self.pdf.read_bytes())])
        code, stdout, _ = self._run("verify", str(signed), "--trust", self.trust)
        self.assertEqual(code, 0, msg=stdout)
        self.assertIn("sin sello de tiempo", stdout)

    def test_sign_pades_rejects_ltv_and_non_pdf(self):
        code, _, stderr = self._run(
            "sign", str(self.pdf), "--format", "pades", "--key", self.key, "--cert", self.cert,
            "--ltv", "--chain", self.trust,
        )
        self.assertEqual(code, 2)
        self.assertIn("pades", stderr)

        text = self.dir / "nota.txt"
        text.write_bytes(b"no soy un pdf")
        out = self.dir / "nota.signed.pdf"
        code, _, stderr = self._run(
            "sign", str(text), "--format", "pades", "--key", self.key, "--cert", self.cert,
            "--no-timestamp",
        )
        self.assertEqual(code, 1)
        self.assertFalse(out.exists())
        self.assertIn("PDF", stderr)


if __name__ == "__main__":
    unittest.main()
