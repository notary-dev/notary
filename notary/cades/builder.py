"""Construye una firma CMS/CAdES-BES usando el firmante proporcionado."""

from datetime import datetime, timezone
from hashlib import sha256
from typing import Callable, List, Optional

from asn1crypto import cms, core, tsp

from notary.cades import ltv as _ltv  # noqa: F401  (registra los atributos CAdES-LT al importar)
from notary.signer.base import Signer


def _signing_certificate_v2_attribute(certificate: core.Asn1Value) -> cms.CMSAttribute:
    """Crea el atributo que vincula los atributos firmados al certificado (RFC 5035)."""
    certificate_hash = sha256(certificate.dump()).digest()
    signing_certificate = tsp.SigningCertificateV2(
        {"certs": [{"cert_hash": certificate_hash}]}
    )
    return cms.CMSAttribute(
        {"type": "signing_certificate_v2", "values": [signing_certificate]}
    )


def _build_signer_info(
    content: bytes,
    signer: Signer,
    timestamper: Optional[Callable[[bytes], bytes]],
    ltv_provider: Optional[Callable[[], List[cms.CMSAttribute]]],
    include_signing_time: bool = True,
) -> cms.SignerInfo:
    """Crea el ``SignerInfo`` de un firmante: atributos firmados, firma y sello."""
    certificate = signer.get_certificate()
    document_digest = sha256(content).digest()
    signing_time = datetime.now(timezone.utc).replace(microsecond=0)

    attributes = [
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [document_digest]}),
    ]
    if include_signing_time:
        attributes.append(
            cms.CMSAttribute(
                {
                    "type": "signing_time",
                    "values": [cms.Time(name="utc_time", value=signing_time)],
                }
            )
        )
    attributes.append(_signing_certificate_v2_attribute(certificate))
    signed_attributes = cms.CMSAttributes(attributes)

    # CMS firma SignedAttrs codificado como SET OF (0x31), no como [0] (0xa0).
    signed_attributes_der = signed_attributes.dump(force=True)
    if not signed_attributes_der.startswith(b"\x31"):
        raise ValueError("Los atributos firmados no tienen la codificación DER SET OF esperada.")
    signature_digest = sha256(signed_attributes_der).digest()
    signature = signer.sign_hash(signature_digest)

    signer_info_fields = {
        "version": "v1",
        "sid": {
            "issuer_and_serial_number": {
                "issuer": certificate.issuer,
                "serial_number": certificate.serial_number,
            }
        },
        "digest_algorithm": {"algorithm": "sha256"},
        "signed_attrs": signed_attributes,
        "signature_algorithm": {"algorithm": "sha256_rsa"},
        "signature": signature,
    }
    if timestamper is not None:
        # El sello cubre el valor de firma (RFC 3161 sobre SignerInfo.signature).
        token = cms.ContentInfo.load(timestamper(signature))
        unsigned_attributes = [
            cms.CMSAttribute(
                {
                    "type": "signature_time_stamp_token",
                    "values": [token],
                }
            )
        ]
        if ltv_provider is not None:
            unsigned_attributes.extend(ltv_provider())
        signer_info_fields["unsigned_attrs"] = cms.CMSAttributes(unsigned_attributes)
    return cms.SignerInfo(signer_info_fields)


def build_cades_bes(
    content: bytes,
    signer: Signer,
    detached: bool = True,
    timestamper: Optional[Callable[[bytes], bytes]] = None,
    ltv_provider: Optional[Callable[[], List[cms.CMSAttribute]]] = None,
    include_signing_time: bool = True,
) -> bytes:
    """Devuelve CMS SignedData DER con una firma CAdES de un solo firmante.

    Con ``detached=True`` el contenido original no se incluye en el resultado.
    Sin ``timestamper`` el resultado es CAdES-BES. Si se indica, recibe el valor
    de firma y devuelve el token RFC 3161 (ContentInfo DER) que se añade como
    atributo no firmado ``signatureTimeStampToken``: el resultado es CAdES-T.
    Si además se indica ``ltv_provider``, se llama después del sello y devuelve
    los atributos no firmados con la cadena y el OCSP (CAdES-LT, ver ``ltv.py``).
    ``include_signing_time=False`` omite ``signingTime``: PAdES lleva la fecha
    declarada en ``/M`` del diccionario de firma, no dentro del CMS.
    """
    if ltv_provider is not None and timestamper is None:
        raise ValueError("la evidencia LTV exige un sello de tiempo previo (CAdES-T)")
    certificate = signer.get_certificate()
    signer_info = _build_signer_info(
        content, signer, timestamper, ltv_provider, include_signing_time
    )

    encapsulated_content = {
        "content_type": "data",
        "content": None if detached else core.OctetString(content),
    }
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": encapsulated_content,
            "certificates": [cms.CertificateChoices(name="certificate", value=certificate)],
            "signer_infos": [signer_info],
        }
    )
    content_info = cms.ContentInfo(
        {"content_type": "signed_data", "content": signed_data}
    )
    # Usamos dump() sin force=True para conservar intactos los bytes DER del
    # certificado y del token de la TSA y evitar re-serializaciones recursivas.
    return content_info.dump()


def add_parallel_signature(
    proof_bytes: bytes,
    content: bytes,
    signer: Signer,
    timestamper: Optional[Callable[[bytes], bytes]] = None,
    ltv_provider: Optional[Callable[[], List[cms.CMSAttribute]]] = None,
) -> bytes:
    """Añade a una firma existente una segunda firma en paralelo (otro ``SignerInfo``).

    Cada firmante firma el documento por su cuenta y lleva su propio sello; las
    firmas anteriores se conservan byte a byte, así que siguen verificando.
    """
    if ltv_provider is not None and timestamper is None:
        raise ValueError("la evidencia LTV exige un sello de tiempo previo (CAdES-T)")
    content_info = cms.ContentInfo.load(proof_bytes)
    signed_data = content_info["content"]
    attached = signed_data["encap_content_info"]["content"].native
    if attached is not None and attached != content:
        raise ValueError("el documento indicado no coincide con el contenido adjunto en la firma")

    certificate = signer.get_certificate()
    already_present = any(
        choice.name == "certificate" and choice.chosen.dump() == certificate.dump()
        for choice in signed_data["certificates"]
    )
    if already_present:
        raise ValueError("ese certificado ya ha firmado este archivo")

    signer_info = _build_signer_info(content, signer, timestamper, ltv_provider)
    signed_data["signer_infos"].append(signer_info)
    signed_data["certificates"].append(
        cms.CertificateChoices(name="certificate", value=certificate)
    )
    return content_info.dump()
