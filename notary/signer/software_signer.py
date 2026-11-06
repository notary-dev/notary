"""Software-backed RSA signer for development and testing."""

from pathlib import Path

from asn1crypto import x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from notary.signer.base import Signer


class SoftwareSigner(Signer):
    """Signs SHA-256 digests with an RSA key stored in an unencrypted PEM file."""

    def __init__(self, key_path: str, cert_path: str) -> None:
        """Load an RSA private key and its matching PEM certificate."""
        key_data = Path(key_path).read_bytes()
        cert_data = Path(cert_path).read_bytes()

        self._private_key = serialization.load_pem_private_key(
            key_data,
            password=None,
        )
        if not isinstance(self._private_key, rsa.RSAPrivateKey):
            raise TypeError("La clave privada debe ser RSA.")

        crypto_certificate = crypto_x509.load_pem_x509_certificate(cert_data)
        self._certificate = asn1_x509.Certificate.load(
            crypto_certificate.public_bytes(serialization.Encoding.DER)
        )

        key_public_bytes = self._private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cert_public_bytes = crypto_certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if key_public_bytes != cert_public_bytes:
            raise ValueError("La clave privada y el certificado no corresponden.")

    def get_certificate(self) -> asn1_x509.Certificate:
        """Return the signer's certificate as an asn1crypto object."""
        return self._certificate

    def sign_hash(self, digest: bytes) -> bytes:
        """Sign a precomputed SHA-256 digest with RSA PKCS#1 v1.5."""
        if len(digest) != 32:
            raise ValueError("El resumen SHA-256 debe tener exactamente 32 bytes.")

        return self._private_key.sign(
            digest,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256()),
        )
