"""Pruebas de la cadena de emisores para CAdES-LT."""

import unittest
from datetime import datetime, timedelta, timezone

import requests
from asn1crypto import x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from notary.evidence import build_issuer_chain

_AIA_URL = "http://pki.example.invalid/ca.crt"


def _name(common_name):
    return crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _issue(subject, issuer, key, issuer_key, aia_url=None):
    now = datetime.now(timezone.utc)
    builder = (
        crypto_x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
    )
    if aia_url:
        builder = builder.add_extension(
            crypto_x509.AuthorityInformationAccess(
                [crypto_x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    crypto_x509.UniformResourceIdentifier(aia_url),
                )]
            ),
            critical=False,
        )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


class _Reply:
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        pass


class IssuerChainTests(unittest.TestCase):
    def setUp(self):
        root_key, ca_key, leaf_key = (rsa.generate_private_key(65537, 2048) for _ in range(3))
        self.root = _issue("Raiz", "Raiz", root_key, root_key)
        # Como AC DNIE 00X: la intermedia no trae AIA hacia su raíz.
        self.ca = _issue("CA", "Raiz", ca_key, root_key)
        self.leaf = _issue("Hoja", "CA", leaf_key, ca_key, aia_url=_AIA_URL)

    def test_stops_at_intermediate_when_its_root_cannot_be_found(self):
        get = lambda url, timeout: _Reply(self.ca.dump())
        chain = build_issuer_chain(self.leaf, get=get)
        self.assertEqual([c.subject for c in chain], [self.ca.subject])

    def test_includes_root_when_given(self):
        get = lambda url, timeout: _Reply(self.ca.dump())
        chain = build_issuer_chain(self.leaf, [self.root], get=get)
        self.assertEqual([c.subject for c in chain], [self.ca.subject, self.root.subject])

    def test_fails_when_not_even_the_direct_issuer_is_found(self):
        def get(url, timeout):
            raise requests.ConnectionError("sin red")

        with self.assertRaises(RuntimeError):
            build_issuer_chain(self.leaf, get=get)


if __name__ == "__main__":
    unittest.main()
