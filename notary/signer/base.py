from abc import ABC, abstractmethod
from asn1crypto import x509


class Signer(ABC):
    @abstractmethod
    def get_certificate(self) -> x509.Certificate:
        """Devuelve el certificado X.509 del firmante."""
        raise NotImplementedError

    @abstractmethod
    def sign_hash(self, digest: bytes) -> bytes:
        """Firma un resumen SHA-256 de 32 bytes y devuelve una firma RSA."""
        raise NotImplementedError
