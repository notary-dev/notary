"""Genera una CA y certificados de prueba para desarrollar Notary sin el DNIe."""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_private_key() -> rsa.RSAPrivateKey:
    """Crea una clave RSA de prueba de 2048 bits."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_private_key(key: rsa.RSAPrivateKey, path: Path) -> None:
    """Guarda la clave privada en PEM/PKCS#8 sin contraseña (solo para pruebas)."""
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def save_certificate(certificate: x509.Certificate, path: Path) -> None:
    """Guarda el certificado X.509 en formato PEM."""
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def create_ca_certificate(
    private_key: rsa.RSAPrivateKey,
    now: datetime,
) -> x509.Certificate:
    """Crea un certificado raíz de prueba autofirmado."""
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Notary Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Notary Test CA"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=365)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )


def create_signer_certificate(
    private_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
    now: datetime,
    validity: timedelta,
    common_name: str,
) -> x509.Certificate:
    """Crea un certificado de firmante emitido por la CA de prueba."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Notary Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + validity).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
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
        .sign(ca_private_key, hashes.SHA256())
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Genera credenciales de prueba; no usa el DNIe ni una clave real."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "test_certs",
        help="Directorio donde guardar los archivos (por defecto: tools/test_certs).",
    )
    parser.add_argument(
        "--short-validity-minutes",
        type=int,
        default=2,
        help="Duración en minutos del certificado corto (por defecto: 2).",
    )
    args = parser.parse_args()

    if args.short_validity_minutes < 1:
        parser.error("--short-validity-minutes debe ser al menos 1.")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    ca_private_key = generate_private_key()
    ca_certificate = create_ca_certificate(ca_private_key, now)
    save_private_key(ca_private_key, args.output_dir / "test_ca.key")
    save_certificate(ca_certificate, args.output_dir / "test_ca.crt")

    signer_private_key = generate_private_key()
    signer_certificate = create_signer_certificate(
        signer_private_key,
        ca_certificate,
        ca_private_key,
        now,
        timedelta(days=30),
        "Notary Test Signer",
    )
    save_private_key(signer_private_key, args.output_dir / "signer.key")
    save_certificate(signer_certificate, args.output_dir / "signer.crt")

    short_private_key = generate_private_key()
    short_certificate = create_signer_certificate(
        short_private_key,
        ca_certificate,
        ca_private_key,
        now,
        timedelta(minutes=args.short_validity_minutes),
        "Notary Short-Lived Signer",
    )
    save_private_key(short_private_key, args.output_dir / "short_signer.key")
    save_certificate(short_certificate, args.output_dir / "short_signer.crt")

    print(f"Credenciales de prueba guardadas en: {args.output_dir}")
    print("Firmante normal: signer.key + signer.crt (válido durante 30 días).")
    print(
        "Firmante de corta duración: short_signer.key + short_signer.crt "
        f"(válido durante {args.short_validity_minutes} minutos)."
    )
    print("CA de prueba: test_ca.crt (su clave privada no debe compartirse).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
