"""Pruebas del cliente TSA y del comando sign (sin DNIe ni red: TSA simulada)."""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from unittest import mock

import requests
from asn1crypto import cms, tsp

from notary import cli, tsa
from notary.signer.software_signer import SoftwareSigner
from tools import generate_test_ca

_TOKEN_OID = "1.2.840.113549.1.9.16.2.14"


def fake_tsa_reply(request_der, status="granted", imprint=None, nonce=None):
    """Construye la respuesta de una TSA simulada (el token no está firmado)."""
    request = tsp.TimeStampReq.load(request_der)
    stamped = imprint
    if stamped is None:
        stamped = request["message_imprint"]["hashed_message"].native
    echoed = nonce
    if echoed is None:
        echoed = request["nonce"].native
    tst_info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": stamped,
            },
            "serial_number": 1,
            "gen_time": datetime(2026, 11, 3, 10, 42, 7, tzinfo=timezone.utc),
            "nonce": echoed,
        }
    )
    token = cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {"content_type": "tst_info", "content": tst_info},
                "signer_infos": [],
            },
        }
    )
    if status in ("granted", "granted_with_mods"):
        return tsp.TimeStampResp(
            {"status": {"status": status}, "time_stamp_token": token}
        ).dump()
    # Una respuesta de rechazo no lleva token: solo PKIStatusInfo dentro de una SEQUENCE.
    status_info = tsp.PKIStatusInfo({"status": status}).dump()
    return b"\x30" + bytes([len(status_info)]) + status_info


class _Reply:
    def __init__(self, content, error=None):
        self.content = content
        self._error = error

    def raise_for_status(self):
        if self._error:
            raise self._error


class TsaClientTests(unittest.TestCase):
    def setUp(self):
        self.signature = b"valor de firma"
        self.imprint = sha256(self.signature).digest()

    def test_request_has_sha256_imprint_nonce_and_cert_req(self):
        request = tsp.TimeStampReq.load(tsa.build_request(self.imprint, 12345))
        self.assertEqual(request["message_imprint"]["hashed_message"].native, self.imprint)
        self.assertEqual(request["nonce"].native, 12345)
        self.assertTrue(request["cert_req"].native)

    def test_nonce_is_positive_and_random(self):
        nonces = {tsa.new_nonce() for _ in range(20)}
        self.assertEqual(len(nonces), 20)
        for nonce in nonces:
            self.assertGreater(nonce, 0)

    def test_stamps_hash_of_signature_value_and_returns_token(self):
        def post(url, data, **kwargs):
            return _Reply(fake_tsa_reply(data))

        token, url = tsa.request_timestamp(
            self.signature, ["http://tsa1"], post=post, log=lambda m: None
        )
        self.assertEqual(url, "http://tsa1")
        info = cms.ContentInfo.load(token)["content"]["encap_content_info"]["content"].parsed
        self.assertEqual(info["message_imprint"]["hashed_message"].native, self.imprint)

    def test_rejects_wrong_nonce(self):
        def post(url, data, **kwargs):
            return _Reply(fake_tsa_reply(data, nonce=1))

        with self.assertRaisesRegex(tsa.TimestampError, "nonce"):
            tsa.request_timestamp(self.signature, ["http://t"], post=post, log=lambda m: None)

    def test_rejects_wrong_imprint(self):
        def post(url, data, **kwargs):
            return _Reply(fake_tsa_reply(data, imprint=sha256(b"otro").digest()))

        with self.assertRaisesRegex(tsa.TimestampError, "no corresponde"):
            tsa.request_timestamp(self.signature, ["http://t"], post=post, log=lambda m: None)

    def test_rejects_rejection_status(self):
        def post(url, data, **kwargs):
            return _Reply(fake_tsa_reply(data, status="rejection"))

        with self.assertRaisesRegex(tsa.TimestampError, "rejection"):
            tsa.request_timestamp(self.signature, ["http://t"], post=post, log=lambda m: None)

    def test_rejects_garbage_response(self):
        def post(url, data, **kwargs):
            return _Reply(b"no es DER")

        with self.assertRaises(tsa.TimestampError):
            tsa.request_timestamp(self.signature, ["http://t"], post=post, log=lambda m: None)

    def test_falls_back_to_next_tsa(self):
        calls = []

        def post(url, data, **kwargs):
            calls.append(url)
            if url == "http://caida":
                raise requests.ConnectionError("sin red")
            return _Reply(fake_tsa_reply(data))

        _, url = tsa.request_timestamp(
            self.signature, ["http://caida", "http://viva"], post=post, log=lambda m: None
        )
        self.assertEqual(url, "http://viva")
        self.assertEqual(calls, ["http://caida", "http://viva"])

    def test_all_tsas_failing_raises_with_each_reason(self):
        def post(url, data, **kwargs):
            raise requests.ConnectionError("sin red")

        with self.assertRaises(tsa.TimestampError) as ctx:
            tsa.request_timestamp(
                self.signature, ["http://a", "http://b"], post=post, log=lambda m: None
            )
        self.assertIn("http://a", str(ctx.exception))
        self.assertIn("http://b", str(ctx.exception))


class SignCommandTests(unittest.TestCase):
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
        cls.doc = cls.dir / "doc.txt"
        cls.doc.write_bytes(b"contenido a firmar")
        cls.key = str(cls.dir / "signer.key")
        cls.cert = str(cls.dir / "signer.crt")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run(self, *argv):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def _fake_request_timestamp(self, signature, urls, **kwargs):
        request = tsa.build_request(sha256(signature).digest(), 7)
        response = tsp.TimeStampResp.load(fake_tsa_reply(request))
        return response["time_stamp_token"].dump(), urls[0]

    def test_no_timestamp_writes_bes_with_warning(self):
        out = self.dir / "bes.csig"
        code, stdout, _ = self._run(
            "sign", str(self.doc), "--key", self.key, "--cert", self.cert,
            "--no-timestamp", "--out", str(out),
        )
        self.assertEqual(code, 0)
        self.assertIn("AVISO", stdout)
        signer_info = cms.ContentInfo.load(out.read_bytes())["content"]["signer_infos"][0]
        self.assertIsNone(signer_info["unsigned_attrs"].native)

    def test_timestamp_is_unsigned_attribute_over_signature_value(self):
        out = self.dir / "t.csig"
        with mock.patch("notary.sign.request_timestamp", self._fake_request_timestamp):
            code, stdout, _ = self._run(
                "sign", str(self.doc), "--key", self.key, "--cert", self.cert,
                "--out", str(out), "--tsa", "http://tsa-simulada",
            )
        self.assertEqual(code, 0)
        self.assertIn("CAdES-T", stdout)
        signer_info = cms.ContentInfo.load(out.read_bytes())["content"]["signer_infos"][0]
        attrs = signer_info["unsigned_attrs"]
        self.assertEqual(len(attrs), 1)
        self.assertEqual(attrs[0]["type"].dotted, _TOKEN_OID)
        token = attrs[0]["values"][0]
        info = token["content"]["encap_content_info"]["content"].parsed
        self.assertEqual(
            info["message_imprint"]["hashed_message"].native,
            sha256(signer_info["signature"].native).digest(),
        )

    def test_signed_attributes_do_not_change_when_stamped(self):
        bes = self.dir / "a.csig"
        stamped = self.dir / "b.csig"
        self._run("sign", str(self.doc), "--key", self.key, "--cert", self.cert,
                  "--no-timestamp", "--out", str(bes))
        with mock.patch("notary.sign.request_timestamp", self._fake_request_timestamp):
            self._run("sign", str(self.doc), "--key", self.key, "--cert", self.cert,
                      "--out", str(stamped), "--tsa", "http://t")
        for path in (bes, stamped):
            signer_info = cms.ContentInfo.load(path.read_bytes())["content"]["signer_infos"][0]
            digest = None
            for attribute in signer_info["signed_attrs"]:
                if attribute["type"].native == "message_digest":
                    digest = attribute["values"][0].native
            self.assertEqual(digest, sha256(b"contenido a firmar").digest())

    def test_all_tsas_failing_writes_nothing_and_fails(self):
        out = self.dir / "nada.csig"

        def failing(signature, urls, **kwargs):
            raise tsa.TimestampError("sin red")

        with mock.patch("notary.sign.request_timestamp", failing):
            code, _, stderr = self._run(
                "sign", str(self.doc), "--key", self.key, "--cert", self.cert,
                "--out", str(out),
            )
        self.assertNotEqual(code, 0)
        self.assertIn("No se escribe ninguna firma sin sello", stderr)
        self.assertFalse(out.exists())

    def test_no_timestamp_with_tsa_is_an_error(self):
        code, _, stderr = self._run(
            "sign", str(self.doc), "--key", self.key, "--cert", self.cert,
            "--no-timestamp", "--tsa", "http://t",
        )
        self.assertNotEqual(code, 0)
        self.assertIn("incompatibles", stderr)

    def test_attached_includes_content(self):
        out = self.dir / "att.csig"
        code, _, _ = self._run(
            "sign", str(self.doc), "--key", self.key, "--cert", self.cert,
            "--no-timestamp", "--format", "attached", "--out", str(out),
        )
        self.assertEqual(code, 0)
        sd = cms.ContentInfo.load(out.read_bytes())["content"]
        self.assertEqual(sd["encap_content_info"]["content"].native, b"contenido a firmar")

    def test_missing_document_fails(self):
        code, _, _ = self._run(
            "sign", str(self.dir / "no_existe"), "--key", self.key, "--cert", self.cert,
            "--no-timestamp",
        )
        self.assertNotEqual(code, 0)

    def test_without_key_the_card_path_is_not_available_yet(self):
        code, _, stderr = self._run("sign", str(self.doc))
        self.assertNotEqual(code, 0)
        self.assertIn("DNIe", stderr)


    def test_card_errors_are_reported_without_traceback(self):
        import PyKCS11

        failing_signer = mock.Mock()
        failing_signer.get_certificate.return_value = SoftwareSigner(
            self.key, self.cert
        ).get_certificate()
        failing_signer.sign_hash.side_effect = PyKCS11.PyKCS11Error(0x00000001)
        with mock.patch("notary.sign.PKCS11Signer", return_value=failing_signer):
            code, _, stderr = self._run("sign", str(self.doc), "--no-timestamp")
        self.assertEqual(code, 1)
        self.assertIn("Error durante la firma", stderr)

        with mock.patch(
            "notary.sign.PKCS11Signer", side_effect=PyKCS11.PyKCS11Error(0x00000030)
        ):
            code, _, stderr = self._run("sign", str(self.doc), "--no-timestamp")
        self.assertEqual(code, 1)
        self.assertIn("No se puede preparar la firma", stderr)



if __name__ == "__main__":
    unittest.main()
