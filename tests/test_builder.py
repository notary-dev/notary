"""Pruebas del firmante software y del constructor CAdES-BES (sin DNIe ni red)."""

import io
import tempfile
from contextlib import redirect_stdout
import unittest
from hashlib import sha256
from pathlib import Path

from asn1crypto import cms
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from notary.cades.builder import build_cades_bes
from notary.signer.software_signer import SoftwareSigner
from tools import generate_test_ca


class BuilderTests(unittest.TestCase):
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
        cls.signer = SoftwareSigner(str(cls.dir / "signer.key"), str(cls.dir / "signer.crt"))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _signer_info(self, der):
        return cms.ContentInfo.load(der)["content"]["signer_infos"][0]

    def test_detached_has_no_content_and_required_attributes(self):
        der = build_cades_bes(b"contenido", self.signer, detached=True)
        sd = cms.ContentInfo.load(der)["content"]
        self.assertIsNone(sd["encap_content_info"]["content"].native)
        attrs = {a["type"].dotted: a for a in self._signer_info(der)["signed_attrs"]}
        self.assertEqual(
            set(attrs),
            {"1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4",
             "1.2.840.113549.1.9.5", "1.2.840.113549.1.9.16.2.47"},
        )

    def test_attached_includes_content(self):
        der = build_cades_bes(b"contenido", self.signer, detached=False)
        sd = cms.ContentInfo.load(der)["content"]
        self.assertEqual(sd["encap_content_info"]["content"].native, b"contenido")

    def test_message_digest_and_certificate_hash(self):
        data = b"documento"
        der = build_cades_bes(data, self.signer)
        si = self._signer_info(der)
        attrs = {a["type"].native: a["values"][0] for a in si["signed_attrs"]}
        self.assertEqual(attrs["message_digest"].native, sha256(data).digest())
        raw = attrs["signing_certificate_v2"].dump()
        self.assertIn(sha256(self.signer.get_certificate().dump()).digest(), raw)

    def test_signature_is_over_set_of_signed_attributes(self):
        der = build_cades_bes(b"documento", self.signer)
        si = self._signer_info(der)
        signed = si["signed_attrs"]
        # Re-codificar como SET OF universal (0x31), no con la etiqueta [0] (0xa0).
        set_of = cms.CMSAttributes(list(signed)).dump(force=True)
        self.assertEqual(set_of[0], 0x31)
        cert = crypto_x509.load_pem_x509_certificate((self.dir / "signer.crt").read_bytes())
        # Lanza InvalidSignature si firma y atributos no corresponden.
        cert.public_key().verify(
            si["signature"].native, set_of, padding.PKCS1v15(), hashes.SHA256()
        )

    def test_software_signer_rejects_bad_digest_length(self):
        with self.assertRaises(ValueError):
            self.signer.sign_hash(b"corto")

    def test_software_signer_rejects_mismatched_key_and_cert(self):
        with self.assertRaises(ValueError):
            SoftwareSigner(str(self.dir / "short_signer.key"), str(self.dir / "signer.crt"))


if __name__ == "__main__":
    unittest.main()
