"""Cliente RFC 3161: pide un sello de tiempo sobre el valor de firma."""

import os
from hashlib import sha256
from typing import Callable, List, Tuple

import requests
from asn1crypto import core, tsp

DEFAULT_TSA_URLS = [
    # ACCV primero: es la única de la lista cuyo sello VALIDe admite.
    "http://tss.accv.es:8318/tsa",
    "https://freetsa.org/tsr",
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
    "http://time.certum.pl",
]

_REQUEST_TYPE = "application/timestamp-query"
_REPLY_TYPE = "application/timestamp-reply"


class TimestampError(Exception):
    """La TSA no ha dado un sello utilizable."""


def new_nonce() -> int:
    """Nonce aleatorio de 64 bits, siempre positivo."""
    return int.from_bytes(os.urandom(8), "big") >> 1


def build_request(imprint: bytes, nonce: int) -> bytes:
    """Construye un TimeStampReq DER con SHA-256, el nonce y certReq."""
    request = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": imprint,
            },
            "nonce": nonce,
            "cert_req": True,
        }
    )
    return request.dump()


def parse_response(response_der: bytes, imprint: bytes, nonce: int) -> bytes:
    """Comprueba que la respuesta corresponde a nuestra petición.

    Devuelve el token (ContentInfo DER). No valida la firma ni la cadena de la
    TSA: eso lo hace ``verify``.
    """
    try:
        # Una respuesta de rechazo no lleva token y TimeStampResp no la acepta
        # entera: se lee primero solo el estado.
        status_info = core.load(response_der)[0]
        status = tsp.PKIStatusInfo.load(status_info.dump())["status"].native
        if status not in ("granted", "granted_with_mods"):
            raise TimestampError(f"la TSA ha respondido con estado '{status}'")

        token = tsp.TimeStampResp.load(response_der)["time_stamp_token"]
        tst_info = token["content"]["encap_content_info"]["content"].parsed
        stamped = tst_info["message_imprint"]
        algorithm = stamped["hash_algorithm"]["algorithm"].native
        if algorithm != "sha256":
            raise TimestampError(f"el sello usa {algorithm}, no sha256")
        if stamped["hashed_message"].native != imprint:
            raise TimestampError("el sello no corresponde al valor de firma enviado")
        if tst_info["nonce"].native != nonce:
            raise TimestampError("el nonce de la respuesta no coincide con el enviado")
        return token.dump()
    except TimestampError:
        raise
    except Exception as error:
        raise TimestampError(f"respuesta de la TSA mal formada ({error})")


def request_timestamp(
    signature_value: bytes,
    tsa_urls: List[str],
    post: Callable = requests.post,
    timeout: float = 15.0,
    log: Callable[[str], None] = print,
) -> Tuple[bytes, str]:
    """Sella el hash del valor de firma probando cada TSA por orden.

    Devuelve (token DER, URL de la TSA que respondió). Si todas fallan lanza
    TimestampError con el motivo de cada una.
    """
    imprint = sha256(signature_value).digest()
    failures = []
    for url in tsa_urls:
        nonce = new_nonce()
        try:
            reply = post(
                url,
                data=build_request(imprint, nonce),
                headers={"Content-Type": _REQUEST_TYPE, "Accept": _REPLY_TYPE},
                timeout=timeout,
            )
            reply.raise_for_status()
            token = parse_response(reply.content, imprint, nonce)
        except (requests.RequestException, TimestampError) as error:
            log(f"      {url}: fallo ({error})")
            failures.append(f"{url}: {error}")
            continue
        return token, url
    raise TimestampError("ninguna TSA ha dado un sello: " + "; ".join(failures))
