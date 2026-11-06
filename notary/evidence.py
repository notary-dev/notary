"""Recoge la evidencia LTV del firmante: cadena de certificados y respuesta OCSP."""

from typing import Callable, List, Optional

import requests
from asn1crypto import cms, pem, x509 as asn1_x509

from notary.cades.ltv import build_ltv_attributes
from notary.ocsp import OcspIndeterminate, OcspInvalid, fetch_ocsp_response

_MAX_CHAIN_LENGTH = 6


def ca_issuer_urls(cert: asn1_x509.Certificate) -> List[str]:
    """URLs de descarga del certificado emisor (AIA, método caIssuers)."""
    urls: List[str] = []
    aia = cert.authority_information_access_value
    if aia is None:
        return urls
    for description in aia:
        if description["access_method"].native == "ca_issuers":
            location = description["access_location"]
            if location.name == "uniform_resource_identifier":
                urls.append(location.native)
    return urls


def _load_certificate(raw: bytes) -> asn1_x509.Certificate:
    if pem.detect(raw):
        _, _, raw = pem.unarmor(raw)
    cert = asn1_x509.Certificate.load(raw)
    _ = cert.native
    return cert


def _find_issuer(
    cert: asn1_x509.Certificate,
    candidates: List[asn1_x509.Certificate],
    get: Callable,
    timeout: float,
) -> Optional[asn1_x509.Certificate]:
    """Busca el emisor entre los certificados dados y, si no está, lo descarga por AIA."""
    for candidate in candidates:
        if candidate.subject == cert.issuer:
            return candidate
    for url in ca_issuer_urls(cert):
        try:
            reply = get(url, timeout=timeout)
            reply.raise_for_status()
            downloaded = _load_certificate(reply.content)
        except (requests.RequestException, ValueError):
            continue
        if downloaded.subject == cert.issuer:
            return downloaded
    return None


def build_issuer_chain(
    leaf: asn1_x509.Certificate,
    extra_certs: Optional[List[asn1_x509.Certificate]] = None,
    get: Optional[Callable] = None,
    timeout: float = 10.0,
) -> List[asn1_x509.Certificate]:
    """Devuelve los emisores de ``leaf`` hasta la raíz (sin incluir ``leaf``)."""
    if get is None:
        get = requests.get
    candidates = list(extra_certs or [])
    chain: List[asn1_x509.Certificate] = []
    current = leaf
    while current.issuer != current.subject and len(chain) < _MAX_CHAIN_LENGTH:
        issuer = _find_issuer(current, candidates, get, timeout)
        if issuer is None and chain:
            # Las CA intermedias del DNIe no traen AIA hacia su raíz: la raíz es el ancla
            # de confianza y la aporta quien verifica con --trust.
            break
        if issuer is None:
            raise RuntimeError(
                f"no se encuentra el emisor de '{current.subject.human_friendly}': "
                "indica sus certificados con --chain o comprueba la AIA del certificado"
            )
        chain.append(issuer)
        current = issuer
    return chain


def collect_ltv_attributes(
    signer_cert: asn1_x509.Certificate,
    extra_certs: Optional[List[asn1_x509.Certificate]] = None,
    get: Optional[Callable] = None,
    post: Optional[Callable] = None,
) -> List[cms.CMSAttribute]:
    """Cadena y OCSP del firmante como atributos no firmados CAdES-LT.

    Lanza ``RuntimeError`` si no se puede reunir la evidencia: un ``--ltv`` que no
    puede cumplirse debe fallar y no producir una firma que aparente serlo.
    """
    chain = build_issuer_chain(signer_cert, extra_certs, get=get)
    if not chain:
        raise RuntimeError("el certificado del firmante es autofirmado: no hay nada que validar")
    try:
        ocsp_der = fetch_ocsp_response(signer_cert, chain[0], post=post)
    except (OcspIndeterminate, OcspInvalid) as error:
        raise RuntimeError(f"no se ha podido obtener una respuesta OCSP válida: {error}") from error
    return build_ltv_attributes(chain, ocsp_der)
