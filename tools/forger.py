"""Generador de pruebas válidas y defectuosas (lote de pruebas conocidas) para Notary."""

import argparse
import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from asn1crypto import cms, core, tsp, x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from notary.cades.builder import _signing_certificate_v2_attribute, build_cades_bes
from notary.signer.software_signer import SoftwareSigner
from tools import generate_test_ca


def _build_custom_tsa_token(
    imprint: bytes,
    gen_time: datetime,
    tsa_key,
    asn1_tsa_cert: asn1_x509.Certificate,
) -> cms.ContentInfo:
    """Construye un TimeStampToken CMS SignedData sobre ``imprint``."""
    tst_info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.99",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": imprint,
            },
            "serial_number": 99,
            "gen_time": gen_time,
            "nonce": 987654321,
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
    return cms.ContentInfo(
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


def convert_detached_to_attached(proof_bytes: bytes, content_bytes: bytes) -> bytes:
    """Convierte una firma CAdES detached válida en attached sin invalidar firma ni sello."""
    content_info = cms.ContentInfo.load(proof_bytes)
    signed_data = content_info["content"]
    signed_data["encap_content_info"]["content"] = core.OctetString(content_bytes)
    return content_info.dump()


def forge_modified_document(
    proof_bytes: bytes, content_bytes: bytes
) -> Tuple[bytes, bytes]:
    """Defecto 1: altera un byte del documento después de haber sido firmado."""
    if not content_bytes:
        tampered = b"X"
    else:
        tampered = content_bytes + b"\n"
    return proof_bytes, tampered


def forge_timestamp_over_document(
    proof_bytes: bytes,
    content_bytes: bytes,
    tsa_token_builder: Callable[[bytes], bytes],
) -> bytes:
    """Defecto 2: reemplaza el sello por uno calculado sobre el documento en vez de la firma."""
    content_info = cms.ContentInfo.load(proof_bytes)
    signer_info = content_info["content"]["signer_infos"][0]
    bad_token = cms.ContentInfo.load(tsa_token_builder(content_bytes))
    signer_info["unsigned_attrs"] = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {
                    "type": "signature_time_stamp_token",
                    "values": [bad_token],
                }
            )
        ]
    )
    return content_info.dump()


def forge_swapped_timestamp(proof_bytes: bytes, other_token_der: bytes) -> bytes:
    """Defecto 3: sustituye el TimeStampToken por el de otra firma distinta."""
    content_info = cms.ContentInfo.load(proof_bytes)
    signer_info = content_info["content"]["signer_infos"][0]
    other_token = cms.ContentInfo.load(other_token_der)
    signer_info["unsigned_attrs"] = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {
                    "type": "signature_time_stamp_token",
                    "values": [other_token],
                }
            )
        ]
    )
    return content_info.dump()


def forge_tampered_signing_time(proof_bytes: bytes) -> bytes:
    """Defecto 4: modifica signingTime en signedAttrs sin volver a calcular la firma RSA."""
    content_info = cms.ContentInfo.load(proof_bytes)
    signer_info = content_info["content"]["signer_infos"][0]
    for attr in signer_info["signed_attrs"]:
        if attr["type"].native == "signing_time":
            attr["values"] = [
                cms.Time(
                    name="utc_time",
                    value=datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                )
            ]
    # Forzamos re-serialización de signed_attrs alterado.
    signer_info["signed_attrs"] = cms.CMSAttributes(list(signer_info["signed_attrs"]))
    return content_info.dump(force=True)


def forge_mismatched_signing_cert_v2(
    proof_bytes: bytes, replacement_cert: asn1_x509.Certificate
) -> bytes:
    """Defecto 5: sustituye el certificado del firmante manteniendo el signingCertificateV2 original."""
    content_info = cms.ContentInfo.load(proof_bytes)
    signed_data = content_info["content"]
    signed_data["certificates"] = [
        cms.CertificateChoices(name="certificate", value=replacement_cert)
    ]
    signed_data["signer_infos"][0]["sid"] = {
        "issuer_and_serial_number": {
            "issuer": replacement_cert.issuer,
            "serial_number": replacement_cert.serial_number,
        }
    }
    return content_info.dump()


def forge_truncated_proof(proof_bytes: bytes, cut_bytes: int = 40) -> bytes:
    """Defecto 6: trunca el final del archivo .csig para producir un DER incompleto."""
    if len(proof_bytes) <= cut_bytes:
        return proof_bytes[: max(1, len(proof_bytes) // 2)]
    return proof_bytes[:-cut_bytes]


def _create_ephemeral_untrusted_tsa(now: datetime):
    """Crea en memoria una TSA cuya CA no forma parte de los --trust del verificador."""
    ca_key = generate_test_ca.generate_private_key()
    ca_name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Pair TSA"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted Pair TSA Root"),
        ]
    )
    ca_cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=30)).replace(tzinfo=None))
        .add_extension(crypto_x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    tsa_subject = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Pair TSA"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted Pair TSA Signer"),
        ]
    )
    tsa_cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(tsa_subject)
        .issuer_name(ca_cert.subject)
        .public_key(ca_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=30)).replace(tzinfo=None))
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
    asn1_tsa = asn1_x509.Certificate.load(
        tsa_cert.public_bytes(serialization.Encoding.DER)
    )
    return ca_key, asn1_tsa


def generate_pair_exchange_set(
    output_dir: Path,
    base_proof_bytes: bytes,
    base_content_bytes: bytes,
    second_valid_proof_bytes: Optional[bytes] = None,
    second_valid_content_bytes: Optional[bytes] = None,
) -> List[Dict[str, str]]:
    """Genera las 6 pruebas del lote de pruebas (2 válidas y 4 defectuosas) y su Answer Key.

    A partir de una prueba real ``base_proof_bytes`` (por ejemplo, firmada con el DNIe y
    una TSA pública), construye las 6 pruebas sin necesidad de volver a introducir el PIN:
      - proof_01: Firma CAdES-T detached original intacta -> VALID
      - proof_02: Segunda firma válida (o conversión CAdES-T attached de la base) -> VALID
      - proof_03: Documento alterado después de firmar (messageDigest no coincide) -> INVALID
      - proof_04: Sello de tiempo calculado sobre el documento en vez de la firma -> INVALID
      - proof_05: Sello de tiempo emitido por una TSA cuya raíz no es de confianza -> INDETERMINATE
      - proof_06: Archivo .csig truncado / corrupto -> INVALID
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    untrusted_key, untrusted_tsa_cert = _create_ephemeral_untrusted_tsa(now)

    # Extraer el certificado de la TSA original si existe para o bien reutilizar estructura,
    # o usar la clave efímera en proof_04 (el fallo de imprint se detecta antes que la cadena).
    def _doc_stamp_builder(doc_bytes: bytes) -> bytes:
        tok = _build_custom_tsa_token(
            sha256(doc_bytes).digest(), now, untrusted_key, untrusted_tsa_cert
        )
        return tok.dump()

    def _untrusted_tsa_over_sig(proof_der: bytes) -> bytes:
        ci = cms.ContentInfo.load(proof_der)
        si = ci["content"]["signer_infos"][0]
        sig_bytes = si["signature"].native
        tok = _build_custom_tsa_token(
            sha256(sig_bytes).digest(), now, untrusted_key, untrusted_tsa_cert
        )
        si["unsigned_attrs"] = cms.CMSAttributes(
            [
                cms.CMSAttribute(
                    {"type": "signature_time_stamp_token", "values": [tok]}
                )
            ]
        )
        return ci.dump()

    entries: List[Dict[str, str]] = []

    # Prueba 1: Válida (detached)
    p1_doc = output_dir / "proof_01.txt"
    p1_sig = output_dir / "proof_01.txt.csig"
    p1_doc.write_bytes(base_content_bytes)
    p1_sig.write_bytes(base_proof_bytes)
    entries.append(
        {
            "id": "proof_01",
            "proof": p1_sig.name,
            "content": p1_doc.name,
            "expected_verdict": "VALID",
            "flaw": "Ninguno (firma CAdES-T detached íntegra con sello TSA sobre signatureValue).",
        }
    )

    # Prueba 2: Válida (segunda firma o versión attached de la firma válida)
    if second_valid_proof_bytes is not None:
        p2_sig = output_dir / "proof_02.txt.csig"
        p2_sig.write_bytes(second_valid_proof_bytes)
        if second_valid_content_bytes is not None:
            p2_doc = output_dir / "proof_02.txt"
            p2_doc.write_bytes(second_valid_content_bytes)
            p2_content_name = p2_doc.name
        else:
            p2_content_name = ""
        entries.append(
            {
                "id": "proof_02",
                "proof": p2_sig.name,
                "content": p2_content_name,
                "expected_verdict": "VALID",
                "flaw": "Ninguno (segunda firma CAdES-T válida).",
            }
        )
    else:
        p2_sig = output_dir / "proof_02_attached.csig"
        p2_sig.write_bytes(
            convert_detached_to_attached(base_proof_bytes, base_content_bytes)
        )
        entries.append(
            {
                "id": "proof_02",
                "proof": p2_sig.name,
                "content": "",
                "expected_verdict": "VALID",
                "flaw": "Ninguno (firma CAdES-T attached con el contenido encapsulado).",
            }
        )

    # Prueba 3: Defectuosa #1 — Documento modificado tras la firma
    p3_bytes, p3_tampered_doc = forge_modified_document(
        base_proof_bytes, base_content_bytes
    )
    p3_doc = output_dir / "proof_03.txt"
    p3_sig = output_dir / "proof_03.txt.csig"
    p3_doc.write_bytes(p3_tampered_doc)
    p3_sig.write_bytes(p3_bytes)
    entries.append(
        {
            "id": "proof_03",
            "proof": p3_sig.name,
            "content": p3_doc.name,
            "expected_verdict": "INVALID",
            "flaw": "El documento fue modificado después de firmarlo (messageDigest no coincide).",
        }
    )

    # Prueba 4: Defectuosa #2 — Sello de tiempo calculado sobre el documento, no sobre la firma
    p4_doc = output_dir / "proof_04.txt"
    p4_sig = output_dir / "proof_04.txt.csig"
    p4_doc.write_bytes(base_content_bytes)
    p4_sig.write_bytes(
        forge_timestamp_over_document(
            base_proof_bytes, base_content_bytes, _doc_stamp_builder
        )
    )
    entries.append(
        {
            "id": "proof_04",
            "proof": p4_sig.name,
            "content": p4_doc.name,
            "expected_verdict": "INVALID",
            "flaw": "El sello de tiempo se calculó sobre el resumen del documento en vez de sobre signatureValue.",
        }
    )

    # Prueba 5: Defectuosa #3 — Sello de tiempo de una TSA no confiable (fuera de --trust)
    p5_doc = output_dir / "proof_05.txt"
    p5_sig = output_dir / "proof_05.txt.csig"
    p5_doc.write_bytes(base_content_bytes)
    p5_sig.write_bytes(_untrusted_tsa_over_sig(base_proof_bytes))
    entries.append(
        {
            "id": "proof_05",
            "proof": p5_sig.name,
            "content": p5_doc.name,
            "expected_verdict": "INDETERMINATE",
            "flaw": "El sello de tiempo proviene de una TSA cuya raíz no está en los --trust del verificador.",
        }
    )

    # Prueba 6: Defectuosa #4 — Archivo .csig truncado / mal formado
    p6_doc = output_dir / "proof_06.txt"
    p6_sig = output_dir / "proof_06.txt.csig"
    p6_doc.write_bytes(base_content_bytes)
    p6_sig.write_bytes(forge_truncated_proof(base_proof_bytes, cut_bytes=40))
    entries.append(
        {
            "id": "proof_06",
            "proof": p6_sig.name,
            "content": p6_doc.name,
            "expected_verdict": "INVALID",
            "flaw": "El archivo .csig está truncado (los últimos 40 bytes DER fueron eliminados).",
        }
    )

    # Guardar Answer Key en JSON y Markdown
    (output_dir / "answer_key.json").write_text(
        json.dumps(entries, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md_lines = [
        "# Clave de Respuestas (Answer Key)",
        "",
        "| Prueba | Archivo `.csig` | Contenido | Veredicto esperado | Defecto / Descripción |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for item in entries:
        content_col = f"`{item['content']}`" if item["content"] else "*(attached)*"
        md_lines.append(
            f"| `{item['id']}` | `{item['proof']}` | {content_col} | "
            f"**`{item['expected_verdict']}`** | {item['flaw']} |"
        )
    (output_dir / "answer_key.md").write_text(
        "\n".join(md_lines) + "\n", encoding="utf-8"
    )

    return entries


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Genera las 6 pruebas del lote de pruebas (2 válidas y 4 defectuosas) y su Answer Key."
    )
    parser.add_argument(
        "--base-proof",
        type=Path,
        default=None,
        help="Ruta a un archivo .csig válido (p. ej. firmado con el DNIe) que servirá de base.",
    )
    parser.add_argument(
        "--base-content",
        type=Path,
        default=None,
        help="Ruta al documento original firmado en --base-proof.",
    )
    parser.add_argument(
        "--second-proof",
        type=Path,
        default=None,
        help="Opcional: segunda firma .csig válida para proof_02.",
    )
    parser.add_argument(
        "--second-content",
        type=Path,
        default=None,
        help="Opcional: documento original de --second-proof.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Genera una firma base de prueba con certificados locales (sin DNIe ni red).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("pair_exchange"),
        help="Carpeta donde escribir las 6 pruebas y answer_key.md (por defecto: pair_exchange).",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        certs_dir = args.output_dir / "test_ca"
        certs_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        ca_key = generate_test_ca.generate_private_key()
        ca_cert = generate_test_ca.create_ca_certificate(ca_key, now)
        generate_test_ca.save_certificate(ca_cert, certs_dir / "test_ca.crt")

        signer_key = generate_test_ca.generate_private_key()
        signer_cert = generate_test_ca.create_signer_certificate(
            signer_key, ca_cert, ca_key, now, timedelta(days=30), "Notary Pair Signer"
        )
        generate_test_ca.save_private_key(signer_key, certs_dir / "signer.key")
        generate_test_ca.save_certificate(signer_cert, certs_dir / "signer.crt")

        tsa_subject = crypto_x509.Name(
            [
                crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Notary Test"),
                crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Notary Test TSA"),
            ]
        )
        tsa_cert_crypto = (
            crypto_x509.CertificateBuilder()
            .subject_name(tsa_subject)
            .issuer_name(ca_cert.subject)
            .public_key(ca_key.public_key())
            .serial_number(crypto_x509.random_serial_number())
            .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
            .not_valid_after((now + timedelta(days=365)).replace(tzinfo=None))
            .add_extension(
                crypto_x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
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
        asn1_tsa = asn1_x509.Certificate.load(
            tsa_cert_crypto.public_bytes(serialization.Encoding.DER)
        )
        signer = SoftwareSigner(
            str(certs_dir / "signer.key"), str(certs_dir / "signer.crt")
        )
        base_content = b"Documento oficial de prueba de Notary."
        base_proof = build_cades_bes(
            base_content,
            signer,
            detached=True,
            timestamper=lambda sig: _build_custom_tsa_token(
                sha256(sig).digest(), now, ca_key, asn1_tsa
            ).dump(),
        )
        second_proof = None
        second_content = None
    else:
        if not args.base_proof or not args.base_content:
            parser.error(
                "Indica --base-proof y --base-content, o usa --self-test para pruebas locales."
            )
        base_proof = args.base_proof.read_bytes()
        base_content = args.base_content.read_bytes()
        second_proof = (
            args.second_proof.read_bytes() if args.second_proof else None
        )
        second_content = (
            args.second_content.read_bytes() if args.second_content else None
        )

    entries = generate_pair_exchange_set(
        args.output_dir,
        base_proof,
        base_content,
        second_valid_proof_bytes=second_proof,
        second_valid_content_bytes=second_content,
    )
    print(f"Generadas {len(entries)} pruebas en: {args.output_dir}")
    for item in entries:
        print(f"  - {item['id']} ({item['proof']}): {item['expected_verdict']} — {item['flaw']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

