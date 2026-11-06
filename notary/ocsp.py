"""Cliente y verificador OCSP (RFC 6960) para comprobar la revocación de certificados."""

import os
from datetime import datetime, timedelta, timezone
from hashlib import sha1, sha256, sha384, sha512
from typing import Callable, List, Optional, Tuple

import requests
from asn1crypto import x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

_OCSP_REQUEST_TYPE = "application/ocsp-request"
_OCSP_RESPONSE_TYPE = "application/ocsp-response"

# Margen por relojes desajustados y duración máxima aceptada de una respuesta sin nextUpdate.
_CLOCK_SKEW = timedelta(minutes=5)
_MAX_AGE_WITHOUT_NEXT_UPDATE = timedelta(hours=24)

_HASH_BY_NAME = {
    "sha1": sha1,
    "sha256": sha256,
    "sha384": sha384,
    "sha512": sha512,
}


class OcspInvalid(Exception):
    """El certificado está revocado o la respuesta OCSP es criptográficamente inválida."""


class OcspIndeterminate(Exception):
    """No se ha podido obtener un estado OCSP concluyente (red caída, UNKNOWN, etc.)."""


def extract_ocsp_urls(cert: asn1_x509.Certificate) -> List[str]:
    """Extrae las URLs de OCSP de la extensión Authority Information Access (AIA)."""
    return list(cert.ocsp_urls)


def build_ocsp_request(
    signer_cert: asn1_x509.Certificate,
    issuer_cert: asn1_x509.Certificate,
    nonce: Optional[bytes] = None,
) -> bytes:
    """Construye una petición OCSP DER para ``signer_cert`` emitido por ``issuer_cert``.

    Con ``nonce`` lo añade como extensión (RFC 6960 §4.4.1) para evitar repeticiones.
    """
    crypto_signer = crypto_x509.load_der_x509_certificate(signer_cert.dump())
    crypto_issuer = crypto_x509.load_der_x509_certificate(issuer_cert.dump())
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(crypto_signer, crypto_issuer, hashes.SHA1())
    if nonce is not None:
        builder = builder.add_extension(crypto_x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


def _verify_raw_signature(
    public_key,
    signature: bytes,
    data: bytes,
    hash_alg: Optional[hashes.HashAlgorithm],
) -> None:
    """Verifica una firma X.509/OCSP sobre ``data`` con ``public_key``."""
    if hash_alg is None:
        raise OcspInvalid("algoritmo de hash no especificado en la firma OCSP")
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), hash_alg)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_alg))
    else:
        raise OcspInvalid("tipo de clave pública del responder OCSP no soportado")


def _verify_ocsp_responder_signature(
    resp: ocsp.OCSPResponse,
    crypto_issuer: crypto_x509.Certificate,
) -> None:
    """Verifica la firma de la respuesta OCSP contra el emisor o un responder delegado."""
    # 1. Probar si la respuesta está firmada directamente por la CA emisora.
    try:
        _verify_raw_signature(
            crypto_issuer.public_key(),
            resp.signature,
            resp.tbs_response_bytes,
            resp.signature_hash_algorithm,
        )
        return
    except InvalidSignature:
        pass

    # 2. Buscar un certificado delegado de OCSP Responder incluido en la respuesta.
    for candidate in resp.certificates:
        try:
            candidate.verify_directly_issued_by(crypto_issuer)
        except Exception:
            continue
        try:
            eku = candidate.extensions.get_extension_for_class(
                crypto_x509.ExtendedKeyUsage
            ).value
            if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                raise OcspInvalid(
                    "el certificado del responder OCSP delegado no tiene EKU id-kp-OCSPSigning"
                )
        except crypto_x509.ExtensionNotFound:
            raise OcspInvalid(
                "el certificado del responder OCSP delegado no incluye ExtendedKeyUsage"
            )
        except ValueError as error:
            # Algunos servidores (FreeTSA) mandan un responder con extensiones que
            # la biblioteca no sabe leer: no se puede validar, pero tampoco es un ataque.
            raise OcspIndeterminate(
                f"no se puede leer el certificado del responder OCSP delegado ({error})"
            )
        try:
            _verify_raw_signature(
                candidate.public_key(),
                resp.signature,
                resp.tbs_response_bytes,
                resp.signature_hash_algorithm,
            )
            return
        except InvalidSignature:
            raise OcspInvalid("la firma de la respuesta OCSP delegada no es válida")

    if not resp.certificates:
        raise OcspInvalid(
            "la firma de la respuesta OCSP no coincide con el emisor y no incluye certificado delegado"
        )
    raise OcspInvalid("ningún certificado en la respuesta OCSP valida su firma")


def _check_nonce(resp: ocsp.OCSPResponse, expected_nonce: Optional[bytes]) -> None:
    """Si se envió un nonce y la respuesta trae otro, es una respuesta repetida."""
    if expected_nonce is None:
        return
    try:
        received = resp.extensions.get_extension_for_class(crypto_x509.OCSPNonce).value.nonce
    except crypto_x509.ExtensionNotFound:
        return
    if received != expected_nonce:
        raise OcspInvalid("el nonce de la respuesta OCSP no coincide con el de la petición")


def _check_freshness(resp: ocsp.OCSPResponse, now: datetime) -> None:
    """Comprueba que ``now`` cae dentro del periodo de validez de la respuesta (RFC 6960 §4.2.2.1)."""
    this_update = resp.this_update_utc
    next_update = resp.next_update_utc
    if this_update > now + _CLOCK_SKEW:
        raise OcspIndeterminate(
            f"la respuesta OCSP es del futuro (thisUpdate {this_update.isoformat()})"
        )
    if next_update is not None:
        if now > next_update + _CLOCK_SKEW:
            raise OcspIndeterminate(
                f"la respuesta OCSP está caducada (nextUpdate {next_update.isoformat()}): "
                "podría ser una respuesta antigua repetida"
            )
    elif now - this_update > _MAX_AGE_WITHOUT_NEXT_UPDATE:
        raise OcspIndeterminate(
            "la respuesta OCSP no indica nextUpdate y tiene más de 24 horas"
        )


def verify_ocsp_response(
    response_der: bytes,
    signer_cert: asn1_x509.Certificate,
    issuer_cert: asn1_x509.Certificate,
    eval_time: Optional[datetime] = None,
    expected_nonce: Optional[bytes] = None,
    now: Optional[datetime] = None,
) -> str:
    """Valida una respuesta OCSP DER y devuelve 'GOOD' o lanza OcspInvalid/OcspIndeterminate.

    Con ``now`` se exige que la respuesta esté vigente en ese instante
    (``thisUpdate <= now <= nextUpdate``). Con ``expected_nonce`` se rechaza una
    respuesta cuyo nonce no coincide; si el servidor no devuelve nonce se acepta,
    porque muchos no lo soportan, y entonces solo protege la ventana de vigencia.
    Las respuestas incrustadas en la firma (LTV) se validan sin ``now``.
    """
    try:
        resp = ocsp.load_der_ocsp_response(response_der)
    except Exception as error:
        raise OcspIndeterminate(f"respuesta OCSP mal formada ({error})")

    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise OcspIndeterminate(
            f"el servidor OCSP devolvió estado {resp.response_status.name}"
        )

    crypto_signer = crypto_x509.load_der_x509_certificate(signer_cert.dump())
    crypto_issuer = crypto_x509.load_der_x509_certificate(issuer_cert.dump())

    if resp.serial_number != crypto_signer.serial_number:
        raise OcspInvalid(
            "el número de serie de la respuesta OCSP no coincide con el del certificado"
        )

    alg_name = resp.hash_algorithm.name.lower()
    hash_fn = _HASH_BY_NAME.get(alg_name)
    if hash_fn is None:
        raise OcspIndeterminate(f"algoritmo de hash en CertID OCSP no soportado ({alg_name})")

    expected_name_hash = hash_fn(issuer_cert.subject.dump()).digest()
    issuer_pubkey_bytes = issuer_cert["tbs_certificate"]["subject_public_key_info"][
        "public_key"
    ].contents
    # BitString en ASN.1 tiene 1 byte inicial de unused bits (0x00).
    if issuer_pubkey_bytes.startswith(b"\x00"):
        issuer_pubkey_bytes = issuer_pubkey_bytes[1:]
    expected_key_hash = hash_fn(issuer_pubkey_bytes).digest()

    if resp.issuer_name_hash != expected_name_hash or resp.issuer_key_hash != expected_key_hash:
        raise OcspInvalid("el CertID de la respuesta OCSP no corresponde al emisor del certificado")

    _verify_ocsp_responder_signature(resp, crypto_issuer)
    _check_nonce(resp, expected_nonce)
    if now is not None:
        _check_freshness(resp, now)

    status = resp.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return "GOOD"
    if status == ocsp.OCSPCertStatus.UNKNOWN:
        raise OcspIndeterminate("el servidor OCSP informa de estado UNKNOWN para el certificado")
    if status == ocsp.OCSPCertStatus.REVOKED:
        rev_time = resp.revocation_time_utc
        rev_str = rev_time.strftime("%Y-%m-%d %H:%M:%S UTC") if rev_time else "desconocida"
        if eval_time is not None and rev_time is not None and rev_time > eval_time:
            # Revocado después de la hora de evaluación (TSA o --at): la firma ya existía.
            return "GOOD"
        raise OcspInvalid(f"el certificado está REVOCADO (fecha de revocación: {rev_str})")

    raise OcspIndeterminate(f"estado de certificado OCSP desconocido ({status})")


def _query_ocsp(
    signer_cert: asn1_x509.Certificate,
    issuer_cert: asn1_x509.Certificate,
    eval_time: Optional[datetime],
    post: Optional[Callable],
    timeout: float,
) -> Optional[Tuple[str, str, bytes]]:
    """Consulta los responders de la AIA y devuelve (estado, url, respuesta DER) o None."""
    if post is None:
        post = requests.post
    urls = extract_ocsp_urls(signer_cert)
    if not urls:
        return None

    nonce = os.urandom(16)
    request_der = build_ocsp_request(signer_cert, issuer_cert, nonce=nonce)
    failures: List[str] = []
    for url in urls:
        try:
            reply = post(
                url,
                data=request_der,
                headers={
                    "Content-Type": _OCSP_REQUEST_TYPE,
                    "Accept": _OCSP_RESPONSE_TYPE,
                },
                timeout=timeout,
            )
            reply.raise_for_status()
            status = verify_ocsp_response(
                reply.content,
                signer_cert,
                issuer_cert,
                eval_time=eval_time,
                expected_nonce=nonce,
                now=datetime.now(timezone.utc),
            )
            return status, url, reply.content
        except OcspInvalid:
            raise
        except (requests.RequestException, OcspIndeterminate) as error:
            failures.append(f"{url}: {error}")

    raise OcspIndeterminate(
        "no se pudo verificar el estado OCSP: " + "; ".join(failures)
    )


def fetch_ocsp_response(
    signer_cert: asn1_x509.Certificate,
    issuer_cert: asn1_x509.Certificate,
    post: Optional[Callable] = None,
    timeout: float = 10.0,
) -> bytes:
    """Obtiene y valida una respuesta OCSP ``good`` para incrustarla en la firma (LTV)."""
    result = _query_ocsp(signer_cert, issuer_cert, None, post, timeout)
    if result is None:
        raise OcspIndeterminate("el certificado no declara ninguna URL OCSP en su AIA")
    return result[2]


def check_ocsp_revocation(
    signer_cert: asn1_x509.Certificate,
    issuer_cert: asn1_x509.Certificate,
    eval_time: Optional[datetime] = None,
    post: Optional[Callable] = None,
    timeout: float = 10.0,
) -> Optional[Tuple[str, str]]:
    """Consulta el estado de revocación OCSP usando las URLs de la extensión AIA.

    Devuelve ``None`` si el certificado no incluye URLs OCSP en AIA, o ``("GOOD", url)``
    si el servidor confirma que el certificado es válido. Lanza ``OcspInvalid`` si está
    revocado o ``OcspIndeterminate`` si no se puede obtener respuesta válida.
    """
    result = _query_ocsp(signer_cert, issuer_cert, eval_time, post, timeout)
    if result is None:
        return None
    return result[0], result[1]
