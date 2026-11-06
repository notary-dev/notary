"""Comando ``sign``: firma un archivo con CAdES y, salvo --no-timestamp, lo sella."""

import sys
from pathlib import Path
from typing import List, Optional

import PyKCS11
from pypdf.errors import PyPdfError
from asn1crypto import pem, x509 as asn1_x509
from cryptography.exceptions import InvalidSignature

from notary.cades.builder import add_parallel_signature, build_cades_bes
from notary.evidence import collect_ltv_attributes
from notary.pades import sign_pdf
from notary.signer.pkcs11_signer import PKCS11Signer
from notary.signer.software_signer import SoftwareSigner
from notary.tsa import DEFAULT_TSA_URLS, TimestampError, request_timestamp


def load_certificates(paths: Optional[List[str]]) -> List[asn1_x509.Certificate]:
    """Carga certificados PEM o DER indicados con --chain."""
    certificates: List[asn1_x509.Certificate] = []
    for path in paths or []:
        raw = Path(path).read_bytes()
        if pem.detect(raw):
            for _, _, der in pem.unarmor(raw, multiple=True):
                certificates.append(asn1_x509.Certificate.load(der))
        else:
            certificates.append(asn1_x509.Certificate.load(raw))
    return certificates


def run_sign(
    file: str,
    fmt: str = "detached",
    tsa_urls: Optional[List[str]] = None,
    out: Optional[str] = None,
    key: Optional[str] = None,
    cert: Optional[str] = None,
    no_timestamp: bool = False,
    module: Optional[str] = None,
    ltv: bool = False,
    chain: Optional[List[str]] = None,
    base_proof: Optional[str] = None,
) -> int:
    """Firma ``file``. Devuelve 0 si se ha escrito la prueba y distinto de 0 si no."""
    if no_timestamp and tsa_urls:
        print("[!] --no-timestamp y --tsa son incompatibles.", file=sys.stderr)
        return 2
    if bool(key) != bool(cert):
        print("[!] --key y --cert deben indicarse juntos.", file=sys.stderr)
        return 2
    if fmt == "pades" and (ltv or base_proof):
        print(
            "[!] --format pades no admite --ltv ni cosign: para añadir otro firmante, "
            "firma de nuevo el PDF ya firmado.",
            file=sys.stderr,
        )
        return 2
    if ltv and no_timestamp:
        print("[!] --ltv exige sello de tiempo: es incompatible con --no-timestamp.", file=sys.stderr)
        return 2
    if chain and not ltv:
        print("[!] --chain solo tiene sentido junto con --ltv.", file=sys.stderr)
        return 2
    if key and module:
        print(
            "[!] --module solo aplica a la firma con DNIe y no puede combinarse con --key/--cert.",
            file=sys.stderr,
        )
        return 2

    if base_proof:
        default_out = base_proof[:-5] + ".multi.csig" if base_proof.endswith(".csig") else base_proof + ".multi.csig"
        out_path = Path(out) if out else Path(default_out)
    elif fmt == "pades":
        out_path = Path(out) if out else Path(str(Path(file).with_suffix("")) + ".signed.pdf")
    else:
        out_path = Path(out) if out else Path(file + ".csig")
    detached = fmt in ("detached", "pades")

    try:
        content = Path(file).read_bytes()
        extra_certs = load_certificates(chain)
        base_bytes = Path(base_proof).read_bytes() if base_proof else None
        if key and cert:
            signer = SoftwareSigner(key, cert)
        else:
            signer = PKCS11Signer(module_path=module)
    except (OSError, ValueError, TypeError, RuntimeError, PyKCS11.PyKCS11Error) as error:
        print(f"[!] No se puede preparar la firma: {error}", file=sys.stderr)
        return 1

    print(f"[1] Documento ..................... {file} ({len(content)} bytes)")
    print(f"[2] Formato ....................... {'PAdES' if fmt == 'pades' else 'CAdES ' + fmt}")
    print(f"[3] Firmante ...................... {signer.get_certificate().subject.human_friendly}")

    timestamper = None
    if no_timestamp:
        print("[4] Sello de tiempo ............... OMITIDO (--no-timestamp)")
    else:
        urls = tsa_urls or DEFAULT_TSA_URLS
        print("[4] Sello de tiempo ............... solicitando a la TSA")

        def timestamper(signature: bytes) -> bytes:
            token, url = request_timestamp(signature, urls)
            print(f"      sellado por {url}")
            return token

    step = 5
    ltv_provider = None
    if ltv:
        print(f"[{step}] Evidencia LTV ................. cadena y OCSP del firmante tras el sello")
        step += 1

        def ltv_provider():
            return collect_ltv_attributes(signer.get_certificate(), extra_certs)

    try:
        if fmt == "pades":
            def build_cms(signed_bytes: bytes) -> bytes:
                return build_cades_bes(
                    signed_bytes,
                    signer,
                    detached=True,
                    timestamper=timestamper,
                    include_signing_time=False,
                )

            proof = sign_pdf(content, build_cms)
        elif base_bytes is not None:
            proof = add_parallel_signature(
                base_bytes, content, signer, timestamper=timestamper, ltv_provider=ltv_provider
            )
        else:
            proof = build_cades_bes(
                content, signer, detached=detached, timestamper=timestamper, ltv_provider=ltv_provider
            )
    except TimestampError as error:
        print(f"[!] No se ha podido obtener el sello de tiempo: {error}", file=sys.stderr)
        print("[!] No se escribe ninguna firma sin sello.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario. No se escribe ninguna firma.", file=sys.stderr)
        return 130
    except (RuntimeError, ValueError, PyKCS11.PyKCS11Error, InvalidSignature, PyPdfError) as error:
        print(f"[!] Error durante la firma: {error!r}", file=sys.stderr)
        return 1

    try:
        out_path.write_bytes(proof)
    except OSError as error:
        print(f"[!] No se puede escribir {out_path}: {error}", file=sys.stderr)
        return 1
    if no_timestamp:
        result = "PAdES-B-B (sin sello de tiempo)" if fmt == "pades" else "CAdES-BES (sin sello de tiempo)"
        print(f"[{step}] Resultado ..................... {result}")
        declared = "la fecha /M del PDF" if fmt == "pades" else "signingTime"
        print(
            f"[!] AVISO: la única hora de este fichero es {declared}, una "
            "declaración del firmante. No es una prueba de cuándo se firmó."
        )
    else:
        level = "CAdES-LT (sello + evidencia incrustada)" if ltv else "CAdES-T"
        if fmt == "pades":
            level = "PAdES-B-T (CAdES-T dentro del PDF)"
        print(f"[{step}] Resultado ..................... {level}")
    print(f"[{step + 1}] Escrito ....................... {out_path}")
    return 0
