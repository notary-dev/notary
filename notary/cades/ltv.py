"""Evidencia para validación a largo plazo (CAdES-LT): certificados y OCSP dentro de la firma.

Se añaden dos atributos no firmados definidos en ETSI EN 319 122-1:
``certificateValues`` (id-aa-ets-certValues) y ``revocationValues``
(id-aa-ets-revocationValues). Con ellos ``verify`` puede validar la cadena y la
revocación sin red y sin depender de que el servidor OCSP siga respondiendo.
"""

from typing import List, Tuple

from asn1crypto import cms, core, ocsp as asn1_ocsp, x509 as asn1_x509

CERT_VALUES_OID = "1.2.840.113549.1.9.16.2.23"
REVOCATION_VALUES_OID = "1.2.840.113549.1.9.16.2.24"


class CertificateValues(core.SequenceOf):
    _child_spec = asn1_x509.Certificate


class BasicOcspResponses(core.SequenceOf):
    _child_spec = asn1_ocsp.BasicOCSPResponse


class _AnyList(core.SequenceOf):
    _child_spec = core.Any


class RevocationValues(core.Sequence):
    # crlVals y otherRevVals no se generan; se declaran para poder leer firmas ajenas.
    _fields = [
        ("crl_vals", _AnyList, {"explicit": 0, "optional": True}),
        ("ocsp_vals", BasicOcspResponses, {"explicit": 1, "optional": True}),
        ("other_rev_vals", core.Any, {"explicit": 2, "optional": True}),
    ]


class SetOfCertificateValues(core.SetOf):
    _child_spec = CertificateValues


class SetOfRevocationValues(core.SetOf):
    _child_spec = RevocationValues


def _register_attribute_types() -> None:
    """Enseña a ``asn1crypto`` los dos OID de CAdES-LT (no los trae de serie)."""
    cms.CMSAttributeType._map[CERT_VALUES_OID] = "ets_certificate_values"
    cms.CMSAttributeType._reverse_map = None
    cms.CMSAttributeType._map[REVOCATION_VALUES_OID] = "ets_revocation_values"
    cms.CMSAttribute._oid_specs["ets_certificate_values"] = SetOfCertificateValues
    cms.CMSAttribute._oid_specs["ets_revocation_values"] = SetOfRevocationValues


_register_attribute_types()


def _basic_response(response_der: bytes) -> asn1_ocsp.BasicOCSPResponse:
    """Extrae la ``BasicOCSPResponse`` de una ``OCSPResponse`` completa."""
    response = asn1_ocsp.OCSPResponse.load(response_der)
    if response["response_status"].native != "successful":
        raise ValueError("la respuesta OCSP no es 'successful'")
    return response["response_bytes"]["response"].parsed


def build_ltv_attributes(
    chain: List[asn1_x509.Certificate],
    ocsp_response_der: bytes,
) -> List[cms.CMSAttribute]:
    """Crea los atributos no firmados con la cadena y la respuesta OCSP del firmante."""
    attributes = []
    if chain:
        attributes.append(
            cms.CMSAttribute(
                {"type": "ets_certificate_values", "values": [CertificateValues(chain)]}
            )
        )
    revocation = RevocationValues(
        {"ocsp_vals": BasicOcspResponses([_basic_response(ocsp_response_der)])}
    )
    attributes.append(
        cms.CMSAttribute({"type": "ets_revocation_values", "values": [revocation]})
    )
    return attributes


def _wrap_basic_response(basic: asn1_ocsp.BasicOCSPResponse) -> bytes:
    """Reconstruye una ``OCSPResponse`` DER completa a partir de la básica incrustada."""
    return asn1_ocsp.OCSPResponse(
        {
            "response_status": "successful",
            "response_bytes": {
                "response_type": "basic_ocsp_response",
                "response": basic,
            },
        }
    ).dump()


def extract_ltv_evidence(
    signer_info: cms.SignerInfo,
) -> Tuple[List[asn1_x509.Certificate], List[bytes]]:
    """Devuelve (certificados, respuestas OCSP DER) incrustados como evidencia LT."""
    certificates: List[asn1_x509.Certificate] = []
    ocsp_responses: List[bytes] = []
    unsigned_attrs = signer_info["unsigned_attrs"]
    if unsigned_attrs.native is None:
        return certificates, ocsp_responses
    for attr in unsigned_attrs:
        name = attr["type"].native
        if name == "ets_certificate_values":
            for value in attr["values"]:
                for cert in value:
                    certificates.append(cert)
        elif name == "ets_revocation_values":
            for value in attr["values"]:
                ocsp_vals = value["ocsp_vals"]
                if ocsp_vals.native is None:
                    continue
                for basic in ocsp_vals:
                    ocsp_responses.append(_wrap_basic_response(basic))
    return certificates, ocsp_responses
