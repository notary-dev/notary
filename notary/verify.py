"""Comando ``verify``: verifica un archivo de firma CAdES (.csig)."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha1, sha256, sha384, sha512
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from asn1crypto import cms, pem, tsp, x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp as crypto_ocsp

from notary.cades.ltv import extract_ltv_evidence
from notary.pades import extract_pdf_signatures
from notary.ocsp import (
    OcspIndeterminate,
    OcspInvalid,
    check_ocsp_revocation,
    verify_ocsp_response,
)

_HASH_FUNCTIONS = {
    "sha1": sha1,
    "sha256": sha256,
    "sha384": sha384,
    "sha512": sha512,
}

_CRYPTO_HASHES = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class VerificationInvalid(Exception):
    """La prueba incumple una comprobación criptográfica, temporal o de formato."""


class VerificationIndeterminate(Exception):
    """No se puede confirmar la validez por falta de confianza o de información."""


@dataclass
class CmsCheckResult:
    """Datos verificados en la Fase 1A (estructura CMS, atributos y firma)."""

    detached: bool
    document: bytes
    document_digest: bytes
    digest_algorithm: str
    signature_label: str
    signer_info: cms.SignerInfo
    signer_cert: asn1_x509.Certificate
    certificates: List[asn1_x509.Certificate]
    signing_time: Optional[datetime]


@dataclass
class TimestampCheckResult:
    """Datos verificados de un sello de tiempo RFC 3161 (signatureTimeStampToken)."""

    gen_time: datetime
    tsa_cert: asn1_x509.Certificate
    tsa_chain: List[asn1_x509.Certificate]
    imprint_algorithm: str


def _cert_short_name(cert: asn1_x509.Certificate) -> str:
    """Devuelve el Common Name del certificado o su subject completo si no tiene CN."""
    subject = cert.subject.native
    if isinstance(subject, dict) and "common_name" in subject:
        return str(subject["common_name"])
    return cert.subject.human_friendly


def _format_chain(chain: List[asn1_x509.Certificate]) -> str:
    """Formatea una cadena de certificados como 'Hoja -> Intermedia -> Raíz'."""
    return " -> ".join(_cert_short_name(c) for c in chain)


def parse_evaluation_time(at_str: str) -> datetime:
    """Convierte una cadena ISO 8601 (--at) a datetime con zona horaria UTC."""
    cleaned = at_str.strip()
    if cleaned.endswith("Z") or cleaned.endswith("z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError as error:
        raise ValueError(
            f"formato de fecha --at no válido ('{at_str}'); usa ISO 8601, p. ej. 2026-11-03T10:42:07Z"
        ) from error
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_trust_certificates(paths: Optional[List[str]]) -> List[asn1_x509.Certificate]:
    """Carga uno o varios archivos de certificados de confianza (PEM o DER)."""
    if not paths:
        return []
    trusted: List[asn1_x509.Certificate] = []
    for path_str in paths:
        try:
            raw = Path(path_str).read_bytes()
        except OSError as error:
            raise VerificationIndeterminate(
                f"no se puede leer el certificado de confianza '{path_str}' ({error})"
            )
        try:
            if pem.detect(raw):
                for type_name, _, der_bytes in pem.unarmor(raw, multiple=True):
                    if type_name == "CERTIFICATE":
                        cert = asn1_x509.Certificate.load(der_bytes)
                        _ = cert.native
                        trusted.append(cert)
            else:
                cert = asn1_x509.Certificate.load(raw)
                _ = cert.native
                trusted.append(cert)
        except Exception as error:
            raise VerificationIndeterminate(
                f"el archivo --trust '{path_str}' no contiene un certificado válido ({error})"
            )
    if not trusted:
        raise VerificationIndeterminate(
            "los archivos indicados en --trust no contienen ningún certificado"
        )
    return trusted


def _is_ca_certificate(cert: asn1_x509.Certificate) -> bool:
    """Comprueba que el certificado puede emitir otros: ca=True y, si declara KeyUsage, keyCertSign."""
    bc = cert.basic_constraints_value
    if bc is None or bc["ca"].native is not True:
        return False
    usage = cert.key_usage_value
    if usage is not None and "key_cert_sign" not in usage.native:
        return False
    return True


def _verify_cert_signature(
    child: asn1_x509.Certificate,
    issuer: asn1_x509.Certificate,
) -> None:
    """Verifica criptográficamente que ``child`` fue firmado por ``issuer``."""
    try:
        crypto_child = crypto_x509.load_der_x509_certificate(child.dump())
        crypto_issuer = crypto_x509.load_der_x509_certificate(issuer.dump())
        crypto_child.verify_directly_issued_by(crypto_issuer)
    except InvalidSignature:
        raise VerificationInvalid(
            f"la firma del certificado '{_cert_short_name(child)}' no es válida "
            f"para su emisor '{_cert_short_name(issuer)}'"
        )
    except Exception as error:
        raise VerificationInvalid(
            f"no se pudo verificar la firma del certificado '{_cert_short_name(child)}' ({error})"
        )


def verify_certificate_chain(
    leaf: asn1_x509.Certificate,
    embedded_certs: List[asn1_x509.Certificate],
    trust_certs: List[asn1_x509.Certificate],
    role_label: str = "firmante",
) -> List[asn1_x509.Certificate]:
    """Construye y verifica la cadena X.509 desde ``leaf`` hasta un ancla en ``trust_certs``."""
    if not trust_certs:
        raise VerificationIndeterminate(
            f"no se ha configurado ningún certificado raíz con --trust para validar al {role_label}"
        )

    trust_by_der = {c.dump(): c for c in trust_certs}
    pool: List[asn1_x509.Certificate] = []
    seen_pool = set()
    for cert in list(trust_certs) + list(embedded_certs):
        der = cert.dump()
        if der not in seen_pool:
            seen_pool.add(der)
            pool.append(cert)

    chain: List[asn1_x509.Certificate] = [leaf]
    visited = {leaf.dump()}

    while chain[-1].dump() not in trust_by_der:
        current = chain[-1]
        if current.issuer == current.subject:
            raise VerificationIndeterminate(
                f"la cadena del {role_label} termina en '{_cert_short_name(current)}', "
                "que no está incluido en --trust"
            )

        candidates = [
            c
            for c in pool
            if c.subject == current.issuer and c.dump() not in visited
        ]
        if not candidates:
            raise VerificationIndeterminate(
                f"no se encuentra el certificado emisor de '{_cert_short_name(current)}' "
                f"hasta un ancla de --trust (cadena del {role_label} incompleta o no confiable)"
            )

        issuer = candidates[0]
        if not _is_ca_certificate(issuer):
            raise VerificationInvalid(
                f"el emisor '{_cert_short_name(issuer)}' no tiene BasicConstraints CA=TRUE"
            )
        _verify_cert_signature(current, issuer)
        chain.append(issuer)
        visited.add(issuer.dump())

    # Si el certificado alcanzado en --trust tiene su propio emisor dentro de --trust,
    # completamos la cadena hasta la raíz de --trust.
    while True:
        anchor = chain[-1]
        if anchor.issuer == anchor.subject:
            # Un ancla de confianza no necesita comprobar su autofirma (RFC 5280, 6.1):
            # raíces antiguas (Apple, ACCV) van firmadas con SHA-1, que la biblioteca
            # no verifica, y daban INVALID sin ser un problema real.
            if not _is_ca_certificate(anchor):
                raise VerificationInvalid(
                    f"la raíz '{_cert_short_name(anchor)}' no tiene BasicConstraints CA=TRUE"
                )
            break
        parent_candidates = [
            c
            for c in trust_certs
            if c.subject == anchor.issuer and c.dump() not in visited
        ]
        if not parent_candidates:
            break
        parent = parent_candidates[0]
        if not _is_ca_certificate(parent):
            raise VerificationInvalid(
                f"el emisor '{_cert_short_name(parent)}' no tiene BasicConstraints CA=TRUE"
            )
        _verify_cert_signature(anchor, parent)
        chain.append(parent)
        visited.add(parent.dump())

    return chain


def verify_chain_validity_at(
    chain: List[asn1_x509.Certificate],
    eval_time: datetime,
    role_label: str = "firmante",
) -> None:
    """Comprueba que todos los certificados de ``chain`` eran vigentes en ``eval_time``."""
    for cert in chain:
        validity = cert["tbs_certificate"]["validity"]
        not_before: datetime = validity["not_before"].native
        not_after: datetime = validity["not_after"].native
        name = _cert_short_name(cert)
        if eval_time < not_before:
            raise VerificationInvalid(
                f"el certificado ({role_label}) '{name}' aún no era válido en "
                f"{eval_time.isoformat()} (válido desde {not_before.isoformat()})"
            )
        if eval_time > not_after:
            raise VerificationInvalid(
                f"el certificado ({role_label}) '{name}' estaba caducado en "
                f"{eval_time.isoformat()} (caducó el {not_after.isoformat()})"
            )


def _parse_signed_data(
    proof_bytes: bytes, signer_index: int = 0
) -> Tuple[cms.SignedData, cms.SignerInfo]:
    """Parsea el contenedor CMS ContentInfo y extrae SignedData y el SignerInfo indicado."""
    if not proof_bytes:
        raise VerificationInvalid("el archivo de firma está vacío")
    try:
        content_info = cms.ContentInfo.load(proof_bytes)
        if content_info["content_type"].native != "signed_data":
            raise VerificationInvalid(
                f"contentType externo inesperado: {content_info['content_type'].native}"
            )
        signed_data = content_info["content"]
        signer_infos = signed_data["signer_infos"]
        if len(signer_infos) == 0:
            raise VerificationInvalid("el archivo CMS no contiene ningún SignerInfo")
        signer_info = signer_infos[signer_index]
        _ = signer_info["signature"].native
        return signed_data, signer_info
    except VerificationInvalid:
        raise
    except Exception as error:
        raise VerificationInvalid(f"archivo .csig mal formado ({error})")


def count_signers(proof_bytes: bytes) -> int:
    """Número de firmantes (``SignerInfo``) del archivo; lanza VerificationInvalid si no es CMS."""
    signed_data, _ = _parse_signed_data(proof_bytes)
    return len(signed_data["signer_infos"])


def _resolve_document(
    signed_data: cms.SignedData,
    content_path: Optional[str],
    content_bytes: Optional[bytes] = None,
) -> Tuple[bool, bytes]:
    """Obtiene los bytes del documento (detached o attached) y comprueba coherencia.

    ``content_bytes`` lo usa PAdES: son los bytes del PDF cubiertos por ``/ByteRange``.
    """
    encap_info = signed_data["encap_content_info"]
    if encap_info["content_type"].native != "data":
        raise VerificationInvalid(
            f"encapContentInfo no es id-data ({encap_info['content_type'].native})"
        )

    encap_content = encap_info["content"].native
    detached = encap_content is None

    if content_bytes is not None:
        if not detached:
            raise VerificationInvalid("la firma de un PDF debe ser detached")
        return True, content_bytes

    if detached:
        if not content_path:
            raise VerificationInvalid(
                "la firma es detached y requiere indicar el archivo original con --content"
            )
        try:
            return True, Path(content_path).read_bytes()
        except OSError as error:
            raise VerificationInvalid(f"no se puede leer --content ({error})")

    if not isinstance(encap_content, bytes):
        raise VerificationInvalid("el contenido encapsulado en la firma attached no es válido")

    if content_path is not None:
        try:
            external_bytes = Path(content_path).read_bytes()
        except OSError as error:
            raise VerificationInvalid(f"no se puede leer --content ({error})")
        if external_bytes != encap_content:
            raise VerificationInvalid(
                "el archivo indicado en --content no coincide con el contenido adjunto en la firma"
            )

    return False, encap_content


def _extract_certificates(signed_data: cms.SignedData) -> List[asn1_x509.Certificate]:
    """Extrae los certificados X.509 incluidos en SignedData.certificates."""
    certs: List[asn1_x509.Certificate] = []
    if signed_data["certificates"].native is None:
        return certs
    for choice in signed_data["certificates"]:
        if choice.name == "certificate":
            certs.append(choice.chosen)
    return certs


def _find_signer_certificate(
    signer_info: cms.SignerInfo,
    certificates: List[asn1_x509.Certificate],
) -> Optional[asn1_x509.Certificate]:
    """Localiza el certificado del firmante a partir de SignerInfo.sid."""
    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        issuer = sid.chosen["issuer"]
        serial = sid.chosen["serial_number"].native
        for cert in certificates:
            if cert.issuer == issuer and cert.serial_number == serial:
                return cert
    elif sid.name == "subject_key_identifier":
        key_id = sid.chosen.native
        for cert in certificates:
            if cert.key_identifier == key_id:
                return cert
    return None


def _collect_signed_attributes(signer_info: cms.SignerInfo) -> Dict[str, cms.CMSAttribute]:
    """Recorre signed_attrs y comprueba que existen los atributos obligatorios."""
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None or len(signed_attrs) == 0:
        raise VerificationInvalid("SignerInfo no contiene atributos firmados (signedAttrs)")

    attrs: Dict[str, cms.CMSAttribute] = {}
    for attr in signed_attrs:
        name = attr["type"].native
        if name in attrs:
            raise VerificationInvalid(f"atributo firmado duplicado: {name}")
        if len(attr["values"]) == 0:
            raise VerificationInvalid(f"el atributo firmado {name} está vacío")
        attrs[name] = attr
    return attrs


def _verify_signing_certificate_attr(
    attrs: Dict[str, cms.CMSAttribute],
    signer_cert: asn1_x509.Certificate,
    require_attribute: bool = True,
) -> None:
    """Comprueba signingCertificateV2 (o signingCertificate v1) frente al certificado."""
    cert_der = signer_cert.dump()

    if "signing_certificate_v2" in attrs:
        sc_v2 = attrs["signing_certificate_v2"]["values"][0]
        if not isinstance(sc_v2, tsp.SigningCertificateV2):
            sc_v2 = tsp.SigningCertificateV2.load(sc_v2.dump())
        certs = sc_v2["certs"]
        if len(certs) == 0:
            raise VerificationInvalid("signingCertificateV2 no contiene ningún ESSCertIDv2")
        ess_cert = certs[0]
        alg = ess_cert["hash_algorithm"]["algorithm"].native
        hash_fn = _HASH_FUNCTIONS.get(alg)
        if hash_fn is None:
            raise VerificationInvalid(
                f"algoritmo de hash no soportado en signingCertificateV2: {alg}"
            )
        expected_hash = ess_cert["cert_hash"].native
        if hash_fn(cert_der).digest() != expected_hash:
            raise VerificationInvalid(
                "el hash en signingCertificateV2 no coincide con el certificado del firmante"
            )
        return

    if "signing_certificate" in attrs:
        sc_v1 = attrs["signing_certificate"]["values"][0]
        certs = sc_v1["certs"]
        if len(certs) == 0:
            raise VerificationInvalid("signingCertificate no contiene ningún ESSCertID")
        expected_hash = certs[0]["cert_hash"].native
        if sha1(cert_der).digest() != expected_hash:
            raise VerificationInvalid(
                "el hash en signingCertificate no coincide con el certificado del firmante"
            )
        return

    if require_attribute:
        raise VerificationInvalid(
            "falta el atributo firmado signingCertificateV2 (RFC 5035)"
        )


def _signed_attributes_set_of_der(signed_attrs: cms.CMSAttributes) -> bytes:
    """Devuelve la codificación DER SET OF (0x31) de signed_attrs para verificar la firma."""
    raw = signed_attrs.dump()
    if raw.startswith(b"\xa0"):
        return b"\x31" + raw[1:]
    dumped = signed_attrs.dump(force=True)
    if not dumped.startswith(b"\x31"):
        raise VerificationInvalid("no se pudo codificar signedAttrs como SET OF (0x31)")
    return dumped


def _verify_mathematical_signature(
    signer_info: cms.SignerInfo,
    signer_cert: asn1_x509.Certificate,
    digest_alg: str,
) -> str:
    """Verifica criptográficamente SignerInfo.signature sobre SET OF de signed_attrs."""
    hash_cls = _CRYPTO_HASHES.get(digest_alg)
    if hash_cls is None:
        raise VerificationInvalid(f"algoritmo de resumen no soportado: {digest_alg}")

    signed_bytes = _signed_attributes_set_of_der(signer_info["signed_attrs"])
    signature = signer_info["signature"].native
    sig_alg = signer_info["signature_algorithm"].signature_algo

    try:
        crypto_cert = crypto_x509.load_der_x509_certificate(signer_cert.dump())
        public_key = crypto_cert.public_key()
        if sig_alg == "rsassa_pkcs1v15" and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_cls())
            return f"RSA PKCS#1 v1.5 / {digest_alg.upper()}"
        if sig_alg == "ecdsa" and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_bytes, ec.ECDSA(hash_cls()))
            return f"ECDSA / {digest_alg.upper()}"
    except InvalidSignature:
        raise VerificationInvalid(
            "la firma matemática no es válida para los atributos firmados y el certificado"
        )
    except Exception as error:
        raise VerificationInvalid(f"error al verificar la firma matemática ({error})")

    raise VerificationInvalid(
        f"combinación de clave y algoritmo de firma no soportada ({sig_alg})"
    )


def verify_cms_core(
    proof_bytes: bytes,
    content_path: Optional[str] = None,
    signer_index: int = 0,
    content_bytes: Optional[bytes] = None,
    require_signing_cert: bool = True,
) -> CmsCheckResult:
    """Ejecuta las comprobaciones de Fase 1A: formato, resumen, atributos y firma."""
    signed_data, signer_info = _parse_signed_data(proof_bytes, signer_index)
    detached, document = _resolve_document(signed_data, content_path, content_bytes)

    digest_alg = signer_info["digest_algorithm"]["algorithm"].native
    hash_fn = _HASH_FUNCTIONS.get(digest_alg)
    if hash_fn is None:
        raise VerificationInvalid(f"algoritmo de resumen no soportado: {digest_alg}")

    attrs = _collect_signed_attributes(signer_info)

    if "content_type" not in attrs:
        raise VerificationInvalid("falta el atributo firmado contentType")
    if attrs["content_type"]["values"][0].native != "data":
        raise VerificationInvalid(
            f"contentType firmado inesperado: {attrs['content_type']['values'][0].native}"
        )

    if "message_digest" not in attrs:
        raise VerificationInvalid("falta el atributo firmado messageDigest")
    expected_digest = attrs["message_digest"]["values"][0].native
    document_digest = hash_fn(document).digest()
    if document_digest != expected_digest:
        raise VerificationInvalid(
            "el resumen del documento no coincide con messageDigest (documento modificado)"
        )

    certificates = _extract_certificates(signed_data)
    signer_cert = _find_signer_certificate(signer_info, certificates)
    if signer_cert is None:
        raise VerificationInvalid(
            "el certificado del firmante no se encuentra dentro del archivo .csig"
        )
    _verify_signing_certificate_attr(attrs, signer_cert, require_attribute=require_signing_cert)

    signing_time: Optional[datetime] = None
    if "signing_time" in attrs:
        raw_time = attrs["signing_time"]["values"][0].native
        if isinstance(raw_time, datetime):
            signing_time = raw_time

    sig_label = _verify_mathematical_signature(signer_info, signer_cert, digest_alg)

    return CmsCheckResult(
        detached=detached,
        document=document,
        document_digest=document_digest,
        digest_algorithm=digest_alg,
        signature_label=sig_label,
        signer_info=signer_info,
        signer_cert=signer_cert,
        certificates=certificates,
        signing_time=signing_time,
    )


def _extract_timestamp_token(signer_info: cms.SignerInfo) -> Optional[cms.ContentInfo]:
    """Extrae el atributo no firmado signatureTimeStampToken si está presente."""
    unsigned_attrs = signer_info["unsigned_attrs"]
    if unsigned_attrs.native is None:
        return None
    tokens: List[cms.ContentInfo] = []
    for attr in unsigned_attrs:
        if attr["type"].native == "signature_time_stamp_token":
            if len(attr["values"]) == 0:
                raise VerificationInvalid("el atributo signatureTimeStampToken está vacío")
            token_val = attr["values"][0]
            if not isinstance(token_val, cms.ContentInfo):
                token_val = cms.ContentInfo.load(token_val.dump())
            tokens.append(token_val)
    if len(tokens) > 1:
        raise VerificationInvalid("hay múltiples atributos signatureTimeStampToken")
    return tokens[0] if tokens else None


def _check_tsa_extended_key_usage(tsa_cert: asn1_x509.Certificate) -> None:
    """Comprueba que el certificado de la TSA tiene ExtendedKeyUsage time_stamping (RFC 3161)."""
    eku = tsa_cert.extended_key_usage_value
    if eku is None or "time_stamping" not in set(eku.native):
        raise VerificationInvalid(
            f"el certificado de la TSA '{_cert_short_name(tsa_cert)}' no tiene "
            "ExtendedKeyUsage timeStamping (1.3.6.1.5.5.7.3.8)"
        )
    if "extended_key_usage" not in tsa_cert.critical_extensions:
        raise VerificationInvalid(
            f"el ExtendedKeyUsage del certificado de la TSA '{_cert_short_name(tsa_cert)}' "
            "no es crítico (RFC 3161, 2.3)"
        )


def verify_timestamp_token(
    signer_info: cms.SignerInfo,
    document: bytes,
    trust_certs: List[asn1_x509.Certificate],
) -> Optional[TimestampCheckResult]:
    """Verifica el sello RFC 3161: imprint sobre signatureValue, firma de la TSA y cadena."""
    token = _extract_timestamp_token(signer_info)
    if token is None:
        return None

    try:
        if token["content_type"].native != "signed_data":
            raise VerificationInvalid("el token de sello de tiempo no es CMS SignedData")
        tsa_sd = token["content"]
        encap = tsa_sd["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            raise VerificationInvalid(
                f"el contenido del token TSA no es TSTInfo ({encap['content_type'].native})"
            )
        tst_octets = encap["content"]
        tst_der: bytes = tst_octets.contents
        tst_info: tsp.TSTInfo = tst_octets.parsed
    except VerificationInvalid:
        raise
    except Exception as error:
        raise VerificationInvalid(f"token de sello de tiempo mal formado ({error})")

    stamped = tst_info["message_imprint"]
    imprint_alg = stamped["hash_algorithm"]["algorithm"].native
    hash_fn = _HASH_FUNCTIONS.get(imprint_alg)
    if hash_fn is None:
        raise VerificationInvalid(
            f"algoritmo de hash no soportado en el sello de tiempo: {imprint_alg}"
        )

    imprint_bytes = stamped["hashed_message"].native
    expected_sig_imprint = hash_fn(signer_info["signature"].native).digest()
    if imprint_bytes != expected_sig_imprint:
        if imprint_bytes == hash_fn(document).digest():
            raise VerificationInvalid(
                "el sello de tiempo se calculó sobre el documento en lugar de sobre el valor de firma"
            )
        raise VerificationInvalid(
            "el imprint del sello de tiempo no coincide con el hash del valor de firma"
        )

    tsa_signer_infos = tsa_sd["signer_infos"]
    if len(tsa_signer_infos) != 1:
        raise VerificationInvalid("el token de la TSA no contiene exactamente 1 SignerInfo")
    tsa_si = tsa_signer_infos[0]

    tsa_embedded_certs = _extract_certificates(tsa_sd)
    tsa_cert = _find_signer_certificate(tsa_si, tsa_embedded_certs + trust_certs)
    if tsa_cert is None:
        raise VerificationIndeterminate(
            "el certificado firmante de la TSA no está incluido en el token ni en --trust"
        )

    tsa_digest_alg = tsa_si["digest_algorithm"]["algorithm"].native
    tsa_hash_fn = _HASH_FUNCTIONS.get(tsa_digest_alg)
    if tsa_hash_fn is None:
        raise VerificationInvalid(
            f"algoritmo de resumen de la TSA no soportado: {tsa_digest_alg}"
        )

    tsa_attrs = _collect_signed_attributes(tsa_si)
    if "content_type" not in tsa_attrs or tsa_attrs["content_type"]["values"][0].native != "tst_info":
        raise VerificationInvalid("contentType firmado del token TSA no es id-ct-TSTInfo")
    if "message_digest" not in tsa_attrs:
        raise VerificationInvalid("falta messageDigest en los atributos firmados de la TSA")
    if tsa_attrs["message_digest"]["values"][0].native != tsa_hash_fn(tst_der).digest():
        raise VerificationInvalid("messageDigest del token TSA no coincide con el TSTInfo")

    # RFC 3161 (2.4.1) obliga a la TSA a firmar el ESSCertID de su certificado:
    # sin él, un atacante podría cambiar el certificado indicado en el token.
    _verify_signing_certificate_attr(tsa_attrs, tsa_cert, require_attribute=True)
    _verify_mathematical_signature(tsa_si, tsa_cert, tsa_digest_alg)
    _check_tsa_extended_key_usage(tsa_cert)

    gen_time: datetime = tst_info["gen_time"].native
    tsa_chain = verify_certificate_chain(
        tsa_cert, tsa_embedded_certs, trust_certs, role_label="TSA"
    )
    verify_chain_validity_at(tsa_chain, gen_time, role_label="TSA")

    return TimestampCheckResult(
        gen_time=gen_time,
        tsa_cert=tsa_cert,
        tsa_chain=tsa_chain,
        imprint_algorithm=imprint_alg,
    )


def check_tsa_revocation(ts_result: TimestampCheckResult) -> Optional[Tuple[str, str]]:
    """Consulta por OCSP si el certificado de la TSA estaba revocado al generar el sello.

    Devuelve ``None`` si no hay a quién consultar (sin URL OCSP o sin emisor en la
    cadena) y ``(estado, url)`` en otro caso. Una revocación posterior a ``gen_time``
    no invalida el sello. Es una comprobación de mejor esfuerzo: solo una revocación
    confirmada da INVALID. Si el OCSP no responde, responde UNKNOWN o el certificado de
    la TSA ya caducó (lo normal en sellos antiguos, para eso existe LTV) se informa de
    que no se pudo consultar, sin cambiar el veredicto: varias TSA reales (FreeTSA,
    Certum) tienen un OCSP defectuoso y, si no, sus sellos nunca saldrían VALID.
    """
    chain = ts_result.tsa_chain
    if len(chain) < 2:
        return None
    tsa_cert, issuer = chain[0], chain[1]
    try:
        return check_ocsp_revocation(tsa_cert, issuer, eval_time=ts_result.gen_time)
    except OcspInvalid as error:
        raise VerificationInvalid(f"certificado de la TSA: {error}") from error
    except Exception as error:  # OcspIndeterminate o un fallo al leer lo que manda el servidor
        return (f"NO CONSULTABLE ({error})", "")


def _check_embedded_ocsp(
    signer_cert: asn1_x509.Certificate,
    issuer_cert: asn1_x509.Certificate,
    responses: List[bytes],
    eval_time: datetime,
    tsa_time: datetime,
) -> Optional[str]:
    """Valida la respuesta OCSP incrustada (LTV) del firmante, sin red.

    Devuelve ``None`` si ninguna respuesta incrustada corresponde al firmante.
    La respuesta debe haberse producido después del sello de tiempo: una anterior
    no descarta que el certificado se revocara entre su emisión y el sello.
    """
    for response_der in responses:
        try:
            parsed = crypto_ocsp.load_der_ocsp_response(response_der)
            if parsed.response_status != crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
                continue
            if parsed.serial_number != signer_cert.serial_number:
                continue
            produced_at = parsed.produced_at_utc
        except Exception:
            continue
        try:
            status = verify_ocsp_response(
                response_der, signer_cert, issuer_cert, eval_time=eval_time
            )
        except OcspInvalid as error:
            raise VerificationInvalid(f"respuesta OCSP incrustada: {error}") from error
        except OcspIndeterminate as error:
            raise VerificationIndeterminate(f"respuesta OCSP incrustada: {error}") from error
        if produced_at < tsa_time - timedelta(minutes=5):
            raise VerificationIndeterminate(
                "la respuesta OCSP incrustada es anterior al sello de tiempo "
                f"({produced_at.isoformat()} < {tsa_time.isoformat()}): no demuestra "
                "que el certificado siguiera vigente cuando se selló"
            )
        return status
    return None


def run_verify(
    proof: str,
    content: Optional[str] = None,
    trust: Optional[List[str]] = None,
    at: Optional[str] = None,
) -> int:
    """Verifica ``proof``; cualquier fallo inesperado de parseo se convierte en INVALID."""
    try:
        return _run_verify(proof, content=content, trust=trust, at=at)
    except Exception as error:
        print(f"VEREDICTO: INVALID — archivo de firma mal formado o ilegible ({error})")
        return 1


def _run_verify(
    proof: str,
    content: Optional[str] = None,
    trust: Optional[List[str]] = None,
    at: Optional[str] = None,
) -> int:
    """Verifica ``proof`` e imprime el desglose paso a paso y el veredicto final."""
    explicit_time: Optional[datetime] = None
    if at is not None:
        try:
            explicit_time = parse_evaluation_time(at)
        except ValueError as error:
            print(f"VEREDICTO: INVALID — {error}")
            return 1

    try:
        proof_bytes = Path(proof).read_bytes()
    except OSError as error:
        print(f"VEREDICTO: INVALID — no se puede leer el archivo de firma ({error})")
        return 1

    if proof_bytes.startswith(b"%PDF-"):
        return _verify_pdf(proof_bytes, trust, explicit_time)

    try:
        signer_count = count_signers(proof_bytes)
    except VerificationInvalid as error:
        print(f"VEREDICTO: INVALID — {error}")
        return 1

    if signer_count == 1:
        return _verify_signer(proof_bytes, 0, 1, content, trust, explicit_time)

    # Varias firmas en paralelo: cada una se verifica por separado y el veredicto
    # global es el peor de todos (INVALID > INDETERMINATE > VALID).
    codes = []
    for index in range(signer_count):
        print(f"=== Firmante {index + 1} de {signer_count} ===")
        codes.append(
            _verify_signer(proof_bytes, index, signer_count, content, trust, explicit_time)
        )
    return _print_final_verdict(codes, "firmantes")


def _print_final_verdict(codes: List[int], noun: str) -> int:
    """Veredicto global de varias firmas: el peor de todos (INVALID > INDETERMINATE > VALID)."""
    names = {0: "VALID", 1: "INVALID", 2: "INDETERMINATE"}
    worst = 1 if 1 in codes else (2 if 2 in codes else 0)
    summary = ", ".join(f"{i + 1}: {names[c]}" for i, c in enumerate(codes))
    print(f"VEREDICTO FINAL: {names[worst]} ({len(codes)} {noun}; {summary})")
    return worst


def _verify_pdf(
    pdf_bytes: bytes,
    trust: Optional[List[str]],
    explicit_time: Optional[datetime],
) -> int:
    """Verifica todas las firmas PAdES de un PDF."""
    try:
        signatures = extract_pdf_signatures(pdf_bytes)
    except ValueError as error:
        print(f"VEREDICTO: INVALID — {error}")
        return 1

    codes: List[int] = []
    for index, signature in enumerate(signatures):
        if len(signatures) > 1:
            print(f"=== Firma PDF {index + 1} de {len(signatures)} ===")
        legacy = signature.sub_filter == "adbe.pkcs7.detached"
        label = f"PAdES ({signature.sub_filter or 'sin SubFilter'}), firma CMS detached en PDF"
        if legacy:
            label += " [adbe.pkcs7: sin signingCertificate, no se comprueba ese vínculo]"
        codes.append(
            _verify_signer(
                signature.cms,
                0,
                1,
                None,
                trust,
                explicit_time,
                content_bytes=signature.signed_content,
                format_label=label,
                require_signing_cert=not legacy,
            )
        )
    if len(codes) == 1:
        return codes[0]
    return _print_final_verdict(codes, "firmas PDF")


def _verify_signer(
    proof_bytes: bytes,
    signer_index: int,
    signer_count: int,
    content: Optional[str],
    trust: Optional[List[str]],
    explicit_time: Optional[datetime],
    content_bytes: Optional[bytes] = None,
    format_label: Optional[str] = None,
    require_signing_cert: bool = True,
) -> int:
    """Verifica un ``SignerInfo`` e imprime el desglose paso a paso y su veredicto."""
    try:
        core_result = verify_cms_core(
            proof_bytes,
            content_path=content,
            signer_index=signer_index,
            content_bytes=content_bytes,
            require_signing_cert=require_signing_cert,
        )
    except VerificationInvalid as error:
        print(f"VEREDICTO: INVALID — {error}")
        return 1

    mode_str = "detached" if core_result.detached else "attached"
    digest_hex = core_result.document_digest.hex()
    short_digest = f"{digest_hex[:8]}...{digest_hex[-8:]}"
    subject_str = core_result.signer_cert.subject.human_friendly

    if format_label is None:
        format_label = f"CAdES {mode_str}, {signer_count} firmante(s)"
    print(f"[1] Formato ....................... {format_label}")
    print(f"[2] Resumen del documento ......... {short_digest} coincide con messageDigest (OK)")
    print(f"[3] Firmante ...................... {subject_str}")
    print("      signingCertificateV2 ........ Coincide con el certificado (OK)")
    print(f"[4] Firma matemática .............. {core_result.signature_label} (OK)")

    try:
        trust_certs = load_trust_certificates(trust)
        ltv_certs, ltv_ocsp = extract_ltv_evidence(core_result.signer_info)
        signer_chain = verify_certificate_chain(
            core_result.signer_cert,
            core_result.certificates + ltv_certs,
            trust_certs,
            role_label="firmante",
        )
        print(f"[5] Cadena de certificación ....... {_format_chain(signer_chain)} (OK)")

        ts_result = verify_timestamp_token(
            core_result.signer_info,
            core_result.document,
            trust_certs,
        )
        if ts_result is not None:
            tsa_name = _cert_short_name(ts_result.tsa_cert)
            gen_str = ts_result.gen_time.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[6] Sello de tiempo (TSA) ......... {tsa_name}, {gen_str}")
            print(
                f"      Imprint {ts_result.imprint_algorithm.upper()}(firma) ...... Coincide (OK)"
            )
            print(
                f"      Cadena de la TSA ............ {_format_chain(ts_result.tsa_chain)} (OK)"
            )
            tsa_ocsp = check_tsa_revocation(ts_result)
            if tsa_ocsp is None:
                print("      Revocación de la TSA ........ No aplica (sin URL OCSP en AIA)")
            else:
                status_str, ocsp_url = tsa_ocsp
                where = f" ({ocsp_url})" if ocsp_url else ""
                print(f"      Revocación de la TSA ........ {status_str}{where}")
        else:
            print(
                "[6] Sello de tiempo (TSA) ......... NO INCLUIDO (CAdES-BES: solo hora declarada)"
            )

        if explicit_time is not None:
            eval_time = explicit_time
            eval_source = f"--at ({eval_time.strftime('%Y-%m-%d %H:%M:%S UTC')})"
        elif ts_result is not None:
            eval_time = ts_result.gen_time
            eval_source = f"hora TSA ({eval_time.strftime('%Y-%m-%d %H:%M:%S UTC')})"
        else:
            eval_time = datetime.now(timezone.utc)
            eval_source = f"hora actual UTC ({eval_time.strftime('%Y-%m-%d %H:%M:%S UTC')})"

        verify_chain_validity_at(signer_chain, eval_time, role_label="firmante")
        print(f"[7] Validez temporal .............. Certificado vigente en {eval_source} (OK)")

        issuer_cert = signer_chain[1] if len(signer_chain) >= 2 else signer_chain[0]
        embedded_status = None
        if ts_result is not None and ltv_ocsp:
            embedded_status = _check_embedded_ocsp(
                core_result.signer_cert, issuer_cert, ltv_ocsp, eval_time, ts_result.gen_time
            )

        ocsp_res = None
        if embedded_status is None:
            try:
                ocsp_res = check_ocsp_revocation(
                    core_result.signer_cert,
                    issuer_cert,
                    eval_time=eval_time,
                )
            except OcspInvalid as error:
                raise VerificationInvalid(str(error)) from error
            except OcspIndeterminate as error:
                raise VerificationIndeterminate(str(error)) from error

        if embedded_status is not None:
            print(
                f"[8] Estado de revocación (OCSP) ... {embedded_status} "
                "(incrustada en la firma, LTV; verificada sin red) (OK)"
            )
        elif ocsp_res is not None:
            status_str, ocsp_url = ocsp_res
            print(f"[8] Estado de revocación (OCSP) ... {status_str} ({ocsp_url}) (OK)")
        else:
            print("[8] Estado de revocación (OCSP) ... No aplica (sin URL OCSP en AIA)")

    except VerificationInvalid as error:
        print(f"VEREDICTO: INVALID — {error}")
        return 1
    except VerificationIndeterminate as error:
        if core_result.signing_time is not None:
            print(f"[9] signingTime (declarada) ....... {core_result.signing_time.isoformat()}")
        print(f"VEREDICTO: INDETERMINATE — {error}")
        return 2

    if core_result.signing_time is not None:
        print(f"[9] signingTime (declarada) ....... {core_result.signing_time.isoformat()}")

    signer_cn = _cert_short_name(core_result.signer_cert)
    if ts_result is not None:
        ts_str = ts_result.gen_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"VEREDICTO: VALID — firmado por {signer_cn}, no más tarde de {ts_str}")
    else:
        print(
            f"VEREDICTO: VALID — firmado por {signer_cn} "
            "(AVISO: archivo sin sello de tiempo; la única fecha que contiene es una declaración del firmante)"
        )
    return 0

