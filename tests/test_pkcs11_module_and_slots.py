"""Pruebas de la selección de módulo y de ranura PKCS#11 (DNIe por lector y DNIe Remote)."""

import unittest
from hashlib import sha256
from pathlib import Path
import tempfile
from unittest import mock

import PyKCS11

from notary import pkcs11_utils
from notary.pin_guard import PinGuard
from notary.signer.pkcs11_signer import PKCS11Signer
from notary.signer.software_signer import SoftwareSigner
from tests.test_cli_and_pkcs11 import Pkcs11SignerTests, _SimulatedP11Lib


def _path(fragment):
    """Ruta por defecto que contiene ``fragment`` (no depende de su posición en la lista)."""
    return next(p for p in pkcs11_utils.DEFAULT_PKCS11_PATHS if fragment in p)


class FindModuleTests(unittest.TestCase):
    def _only_existing(self, *paths):
        return mock.patch.object(
            pkcs11_utils.os.path, "exists", side_effect=lambda p: p in paths
        )

    def test_a_single_installed_module_is_returned_without_loading_it(self):
        opensc = _path("OpenSC Project")
        factory = mock.Mock(side_effect=AssertionError("no debe cargar el módulo para sondearlo"))
        with self._only_existing(opensc), mock.patch.object(pkcs11_utils.PyKCS11, "PyKCS11Lib", factory):
            self.assertEqual(pkcs11_utils.find_pkcs11_module(), opensc)
        factory.assert_not_called()

    def test_with_two_modules_the_one_with_a_token_wins(self):
        remote, opensc = _path("DNIeRemotePKCS11"), _path("OpenSC Project")
        loaded = []

        class Lib:
            def load(self, path):
                loaded.append(path)
                self.path = path

            def getSlotList(self, tokenPresent=False):
                return [1] if self.path == remote else []

        with self._only_existing(remote, opensc), mock.patch.object(pkcs11_utils.PyKCS11, "PyKCS11Lib", Lib):
            self.assertEqual(pkcs11_utils.find_pkcs11_module(), remote)
        self.assertEqual(loaded, [opensc, remote])

    def test_official_dnie_module_is_found_when_opensc_sees_no_token(self):
        opensc, official = _path("OpenSC Project"), _path("UsrPkcs11")
        loaded = []

        class Lib:
            def load(self, path):
                loaded.append(path)
                self.path = path

            def getSlotList(self, tokenPresent=False):
                return [1] if self.path == official else []

        with self._only_existing(opensc, official), mock.patch.object(pkcs11_utils.PyKCS11, "PyKCS11Lib", Lib):
            self.assertEqual(pkcs11_utils.find_pkcs11_module(), official)
        self.assertEqual(loaded, [opensc, official])

    def test_with_two_modules_and_no_token_it_refuses_to_guess(self):
        remote, opensc = _path("DNIeRemotePKCS11"), _path("OpenSC Project")

        class Lib:
            def load(self, path):
                pass

            def getSlotList(self, tokenPresent=False):
                return []

        with self._only_existing(remote, opensc), mock.patch.object(pkcs11_utils.PyKCS11, "PyKCS11Lib", Lib):
            with self.assertRaisesRegex(FileNotFoundError, "ninguno detecta un token"):
                pkcs11_utils.find_pkcs11_module()


class _SlotInfoLib(_SimulatedP11Lib):
    """Biblioteca simulada que, como DNIe Remote, se consulta con getSlotList() + getSlotInfo()."""

    def __init__(self, slot_flags, session):
        super().__init__(flags=0, session=session)
        self.slot_flags = slot_flags
        self.token_present_queries = 0
        self.sessions_opened = 0

    def getSlotList(self, tokenPresent=False):
        if tokenPresent:
            self.token_present_queries += 1
        return list(self.slot_flags)

    def getSlotInfo(self, slot):
        return type("SlotInfo", (), {"flags": self.slot_flags[slot]})()

    def getTokenInfo(self, slot):
        info = super().getTokenInfo(slot)
        info.chosen_slot = slot
        return info

    def openSession(self, slot):
        self.sessions_opened += 1
        return self.session


class SlotSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Pkcs11SignerTests.setUpClass()
        cls.helper = Pkcs11SignerTests("test_digest_info_requires_32_byte_sha256")

    @classmethod
    def tearDownClass(cls):
        Pkcs11SignerTests.tearDownClass()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.guard = PinGuard(Path(self._tmp.name) / "pin_guard.json")
        self.logins = []

    def tearDown(self):
        self._tmp.cleanup()

    def _signer(self, p11, pin="1234"):
        return PKCS11Signer(
            module_path=str(Pkcs11SignerTests.fake_module),
            pin_provider=lambda: pin,
            p11_factory=lambda: p11,
            guard=self.guard,
        )

    def test_the_slot_with_a_token_is_chosen_using_slot_info(self):
        p11 = _SlotInfoLib({1: 0, 2: PyKCS11.CKF_TOKEN_PRESENT}, self.helper._make_session())
        signer = self._signer(p11)
        self.assertEqual(signer._slot, 2)
        # DNIe Remote se rompe con getSlotList(tokenPresent=True): no debe usarse.
        self.assertEqual(p11.token_present_queries, 0)

    def test_without_any_token_it_reports_that_no_dnie_is_present(self):
        p11 = _SlotInfoLib({1: 0, 2: 0}, self.helper._make_session())
        with self.assertRaisesRegex(RuntimeError, "ningún DNIe"):
            self._signer(p11)

    def test_the_session_is_closed_after_signing_and_reopened_for_the_next_one(self):
        session = self.helper._make_session()
        p11 = _SlotInfoLib({1: PyKCS11.CKF_TOKEN_PRESENT}, session)
        signer = self._signer(p11)
        self.assertIsNotNone(signer._session)
        signer.sign_hash(sha256(b"uno").digest())
        self.assertIsNone(signer._session)
        signer.sign_hash(sha256(b"dos").digest())
        self.assertEqual(p11.sessions_opened, 2)

    def test_the_line_break_of_the_pin_prompt_is_not_part_of_the_pin(self):
        session = self.helper._make_session()
        seen = []
        original_login = session.login
        session.login = lambda pin: (seen.append(pin), original_login(pin))[1]
        p11 = _SlotInfoLib({1: PyKCS11.CKF_TOKEN_PRESENT}, session)
        self._signer(p11, pin="1234\r\n").sign_hash(sha256(b"x").digest())
        self.assertEqual(seen, ["1234"])

    def test_an_empty_pin_never_reaches_the_card(self):
        session = self.helper._make_session()
        p11 = _SlotInfoLib({1: PyKCS11.CKF_TOKEN_PRESENT}, session)
        with self.assertRaisesRegex(RuntimeError, "ningún PIN"):
            self._signer(p11, pin="\r\n").sign_hash(sha256(b"x").digest())
        self.assertEqual(session.login_attempts, 0)


class ProtectedPathAndInterruptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Pkcs11SignerTests.setUpClass()
        cls.helper = Pkcs11SignerTests("test_digest_info_requires_32_byte_sha256")

    @classmethod
    def tearDownClass(cls):
        Pkcs11SignerTests.tearDownClass()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.guard = PinGuard(Path(self._tmp.name) / "pin_guard.json")
        self.pin_requests = []

    def tearDown(self):
        self._tmp.cleanup()

    def _signer(self, session, protected=False):
        p11 = _SlotInfoLib({1: PyKCS11.CKF_TOKEN_PRESENT}, session)
        if protected:
            p11.flags = PyKCS11.CKF_PROTECTED_AUTHENTICATION_PATH
        return PKCS11Signer(
            module_path=str(Pkcs11SignerTests.fake_module),
            pin_provider=lambda: (self.pin_requests.append(1) or "1234"),
            p11_factory=lambda: p11,
            guard=self.guard,
        )

    def test_protected_authentication_path_logs_in_with_null_and_never_asks_for_a_pin(self):
        session = self.helper._make_session()
        seen = []
        original_login = session.login
        session.login = lambda pin: (seen.append(pin), original_login(pin))[1]
        self._signer(session, protected=True).sign_hash(sha256(b"x").digest())
        self.assertEqual(seen, [None])
        self.assertEqual(self.pin_requests, [])

    def test_wrong_pin_typed_outside_the_terminal_is_still_counted(self):
        session = self.helper._make_session(login_error=PyKCS11.PyKCS11Error(PyKCS11.CKR_PIN_INCORRECT))
        with self.assertRaisesRegex(RuntimeError, "registrados: 1 de 3"):
            self._signer(session, protected=True).sign_hash(sha256(b"x").digest())

    def test_interrupting_the_login_counts_as_a_spent_attempt(self):
        session = self.helper._make_session()

        def interrupted(pin):
            raise KeyboardInterrupt

        session.login = interrupted
        signer = self._signer(session)
        with self.assertRaises(KeyboardInterrupt):
            signer.sign_hash(sha256(b"x").digest())
        self.assertEqual(self.guard.failed_attempts("TOKEN-DE-PRUEBA"), 1)

    def test_two_interrupted_logins_block_a_third(self):
        session = self.helper._make_session()

        def interrupted(pin):
            raise KeyboardInterrupt

        session.login = interrupted
        signer = self._signer(session)
        for _ in range(2):
            with self.assertRaises(KeyboardInterrupt):
                signer.sign_hash(sha256(b"x").digest())
        with self.assertRaisesRegex(RuntimeError, "PAD"):
            signer.sign_hash(sha256(b"x").digest())
        self.assertEqual(len(self.pin_requests), 2)

    def test_ctrl_c_during_sign_prints_a_message_instead_of_a_traceback(self):
        from contextlib import redirect_stderr, redirect_stdout
        import io

        from notary import cli
        from tests.test_tsa_and_sign import SignCommandTests

        SignCommandTests.setUpClass()
        try:
            doc = SignCommandTests.doc
            fake = mock.Mock()
            fake.get_certificate.return_value = SoftwareSigner(
                SignCommandTests.key, SignCommandTests.cert
            ).get_certificate()
            fake.sign_hash.side_effect = KeyboardInterrupt
            err = io.StringIO()
            with mock.patch("notary.sign.PKCS11Signer", return_value=fake), redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = cli.main(["sign", str(doc), "--no-timestamp"])
            self.assertEqual(code, 130)
            self.assertIn("Interrumpido", err.getvalue())
            self.assertFalse(Path(str(doc) + ".csig").exists())
        finally:
            SignCommandTests.tearDownClass()


if __name__ == "__main__":
    unittest.main()
