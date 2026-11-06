"""PAdES: firma CAdES detached dentro de un PDF y extracción de las firmas de un PDF.

La firma se añade como *actualización incremental*: los bytes del PDF original no
se tocan (así las firmas anteriores siguen verificando) y se anexan, al final, la
firma, un campo de firma invisible, las páginas/catálogo modificados y una nueva
tabla de referencias cruzadas. La firma cubre todo el archivo excepto el valor
``/Contents`` (``/ByteRange``).

Solo se usa ``pypdf`` para *leer* la estructura del PDF; la firma, el sello de
tiempo y la verificación son código propio (sin bibliotecas de firma
de PDF).
"""

import io
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from asn1crypto import cms
from pypdf import PdfReader
from pypdf.errors import PyPdfError
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    PdfObject,
)

# Bytes reservados para la firma CMS (con sello y certificado suelen ocupar 5-9 KB).
SIGNATURE_RESERVE = 20000

_BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")
_SUB_FILTER = re.compile(rb"/SubFilter\s*/([^\s/<>\[\]()]+)")
_STARTXREF = re.compile(rb"startxref\s+(\d+)")


@dataclass
class PdfSignature:
    """Una firma encontrada en un PDF, con los bytes que cubre."""

    sub_filter: str
    cms: bytes
    signed_content: bytes
    range_end: int


def _serialize(obj: PdfObject) -> bytes:
    buffer = io.BytesIO()
    obj.write_to_stream(buffer)
    return buffer.getvalue()


def _copy_dict(source: DictionaryObject) -> DictionaryObject:
    """Copia un diccionario conservando las referencias indirectas sin resolver."""
    copy = DictionaryObject()
    for key in source.keys():
        copy[NameObject(key)] = source.raw_get(key)
    return copy


def _with_appended(
    source: DictionaryObject,
    key: str,
    item: PdfObject,
    rewrites: Dict[int, Tuple[int, PdfObject]],
) -> DictionaryObject:
    """Copia ``source`` añadiendo ``item`` al array ``key``.

    Si el array es un objeto indirecto, se reescribe ese objeto (se anota en
    ``rewrites``) y el diccionario conserva su referencia.
    """
    copy = _copy_dict(source)
    existing = source.raw_get(key) if key in source else None
    if existing is None:
        copy[NameObject(key)] = ArrayObject([item])
    elif isinstance(existing, IndirectObject):
        items = list(existing.get_object())
        items.append(item)
        rewrites[existing.idnum] = (existing.generation, ArrayObject(items))
    else:
        items = list(existing)
        items.append(item)
        copy[NameObject(key)] = ArrayObject(items)
    return copy


def _object_bytes(number: int, generation: int, body: bytes) -> bytes:
    return b"%d %d obj\n" % (number, generation) + body + b"\nendobj\n"


def _pdf_date(moment: datetime) -> bytes:
    return moment.strftime("(D:%Y%m%d%H%M%SZ)").encode("ascii")


def _xref_groups(numbers: List[int]) -> List[Tuple[int, int]]:
    """Agrupa números de objeto consecutivos como (primero, cantidad)."""
    groups: List[Tuple[int, int]] = []
    for number in sorted(numbers):
        if groups and groups[-1][0] + groups[-1][1] == number:
            groups[-1] = (groups[-1][0], groups[-1][1] + 1)
        else:
            groups.append((number, 1))
    return groups


def sign_pdf(
    pdf: bytes,
    build_cms: Callable[[bytes], bytes],
    reserve: int = SIGNATURE_RESERVE,
    now: Optional[datetime] = None,
) -> bytes:
    """Devuelve ``pdf`` con una firma PAdES añadida como actualización incremental.

    ``build_cms`` recibe los bytes cubiertos por la firma (``/ByteRange``) y
    devuelve la firma CAdES detached en DER.
    """
    if not pdf.startswith(b"%PDF-"):
        raise ValueError("el archivo no es un PDF")
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    try:
        reader = PdfReader(io.BytesIO(pdf))
        if reader.is_encrypted:
            raise ValueError("los PDF cifrados no están soportados")
        trailer = reader.trailer
        root_ref = trailer.raw_get("/Root")
        catalog = reader.root_object
        size = int(trailer["/Size"])
        page = reader.pages[0]
        page_ref = page.indirect_reference
    except ValueError:
        raise
    except (PyPdfError, KeyError, IndexError, AttributeError, TypeError) as error:
        raise ValueError(f"PDF no válido o no soportado ({error})") from error
    if not isinstance(root_ref, IndirectObject) or page_ref is None:
        raise ValueError("estructura de PDF no soportada (catálogo o página sin referencia)")

    previous = _STARTXREF.findall(pdf)
    if not previous:
        raise ValueError("el PDF no tiene startxref")
    previous_offset = int(previous[-1])
    uses_xref_stream = pdf[previous_offset : previous_offset + 4] != b"xref"

    signature_number = size
    field_number = size + 1
    xref_number = size + 2 if uses_xref_stream else None
    new_size = size + (3 if uses_xref_stream else 2)
    field_ref = IndirectObject(field_number, 0, reader)

    rewrites: Dict[int, Tuple[int, PdfObject]] = {}
    page_copy = _with_appended(page, "/Annots", field_ref, rewrites)
    rewrites[page_ref.idnum] = (page_ref.generation, page_copy)

    acro_raw = catalog.raw_get("/AcroForm") if "/AcroForm" in catalog else None
    if acro_raw is None:
        acro_copy = DictionaryObject()
        acro_copy[NameObject("/Fields")] = ArrayObject([field_ref])
    else:
        acro_copy = _with_appended(acro_raw.get_object(), "/Fields", field_ref, rewrites)
    acro_copy[NameObject("/SigFlags")] = NumberObject(3)
    if isinstance(acro_raw, IndirectObject):
        rewrites[acro_raw.idnum] = (acro_raw.generation, acro_copy)
    else:
        catalog_copy = _copy_dict(catalog)
        catalog_copy[NameObject("/AcroForm")] = acro_copy
        rewrites[root_ref.idnum] = (root_ref.generation, catalog_copy)

    signature_body = (
        b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached"
        b" /ByteRange [0 %10d %10d %10d] /M " % (0, 0, 0)
        + _pdf_date(moment)
        + b" /Contents <"
        + b"0" * (reserve * 2)
        + b"> >>"
    )
    field_body = (
        b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature%d)"
        b" /V %d 0 R /Rect [0 0 0 0] /F 132 /P %d %d R >>"
        % (field_number, signature_number, page_ref.idnum, page_ref.generation)
    )

    output = bytearray(pdf)
    if not pdf.endswith(b"\n"):
        output += b"\n"
    offsets: Dict[int, int] = {}
    generations: Dict[int, int] = {}

    def append_object(number: int, generation: int, body: bytes) -> int:
        offsets[number] = len(output)
        generations[number] = generation
        start = len(output)
        output.extend(_object_bytes(number, generation, body))
        return start

    signature_start = append_object(signature_number, 0, signature_body)
    append_object(field_number, 0, field_body)
    for number in sorted(rewrites):
        generation, obj = rewrites[number]
        append_object(number, generation, _serialize(obj))

    trailer_extra = b""
    for key in ("/Info", "/ID"):
        if key in trailer:
            trailer_extra += b" " + key.encode("ascii") + b" " + _serialize(trailer.raw_get(key))

    xref_offset = len(output)
    if uses_xref_stream:
        offsets[xref_number] = xref_offset
        generations[xref_number] = 0
        groups = _xref_groups(list(offsets))
        entries = b""
        for first, count in groups:
            for number in range(first, first + count):
                entries += b"\x01" + offsets[number].to_bytes(4, "big")
                entries += generations[number].to_bytes(2, "big")
        index = b" ".join(b"%d %d" % group for group in groups)
        stream_dict = (
            b"<< /Type /XRef /Size %d /W [1 4 2] /Index [%s] /Root %d %d R /Prev %d%s /Length %d >>"
            % (
                new_size, index, root_ref.idnum, root_ref.generation,
                previous_offset, trailer_extra, len(entries),
            )
        )
        append_object(xref_number, 0, stream_dict + b"\nstream\n" + entries + b"\nendstream")
    else:
        output += b"xref\n"
        for first, count in _xref_groups(list(offsets)):
            output += b"%d %d\n" % (first, count)
            for number in range(first, first + count):
                output += b"%010d %05d n \n" % (offsets[number], generations[number])
        output += (
            b"trailer\n<< /Size %d /Root %d %d R /Prev %d%s >>\n"
            % (new_size, root_ref.idnum, root_ref.generation, previous_offset, trailer_extra)
        )
    output += b"startxref\n%d\n%%%%EOF\n" % xref_offset

    # Posición exacta del valor /Contents y relleno del /ByteRange (mismo ancho).
    contents_mark = bytes(output).index(b"/Contents <", signature_start)
    contents_start = contents_mark + len(b"/Contents ")
    contents_end = contents_start + 1 + reserve * 2 + 1
    byte_range = b"/ByteRange [0 %10d %10d %10d]" % (
        contents_start, contents_end, len(output) - contents_end,
    )
    placeholder = b"/ByteRange [0 %10d %10d %10d]" % (0, 0, 0)
    range_position = bytes(output).index(placeholder, signature_start)
    output[range_position : range_position + len(placeholder)] = byte_range

    signed_content = bytes(output[:contents_start]) + bytes(output[contents_end:])
    signature = build_cms(signed_content)
    if len(signature) > reserve:
        raise ValueError(
            f"la firma ocupa {len(signature)} bytes y solo hay {reserve} reservados en el PDF"
        )
    hex_signature = signature.hex().upper().encode("ascii").ljust(reserve * 2, b"0")
    output[contents_start + 1 : contents_start + 1 + reserve * 2] = hex_signature
    return bytes(output)


def extract_pdf_signatures(pdf: bytes) -> List[PdfSignature]:
    """Localiza las firmas de un PDF y devuelve su CMS y los bytes que cubren.

    Lanza ``ValueError`` si alguna firma está mal construida: por ejemplo, si el
    hueco del ``/ByteRange`` no coincide exactamente con el valor ``/Contents``,
    o si queda contenido sin cubrir tras la última firma.
    """
    signatures: List[PdfSignature] = []
    for match in _BYTE_RANGE.finditer(pdf):
        first, gap_start, gap_end, tail = (int(group) for group in match.groups())
        if first != 0 or gap_start >= gap_end or gap_end + tail > len(pdf):
            raise ValueError("/ByteRange de la firma fuera de los límites del archivo")
        gap = pdf[gap_start:gap_end]
        if len(gap) < 4 or gap[:1] != b"<" or gap[-1:] != b">":
            raise ValueError("el hueco del /ByteRange no es el valor hexadecimal de /Contents")
        if not re.search(rb"/Contents\s*$", pdf[max(0, gap_start - 40) : gap_start]):
            raise ValueError("el hueco del /ByteRange no corresponde a /Contents de la firma")

        object_start = max(pdf.rfind(b" obj", 0, match.start()), 0)
        object_end = pdf.find(b"endobj", gap_end)
        if object_end < 0:
            object_end = min(len(pdf), gap_end + 2000)
        header = pdf[object_start : gap_start] + pdf[gap_end:object_end]
        sub_filter_match = _SUB_FILTER.search(header)
        sub_filter = sub_filter_match.group(1).decode("latin-1") if sub_filter_match else ""

        try:
            raw = bytes.fromhex(gap[1:-1].decode("ascii"))
            der = cms.ContentInfo.load(raw).dump()
        except Exception as error:
            raise ValueError(f"/Contents no contiene una firma CMS válida ({error})") from error

        signatures.append(
            PdfSignature(
                sub_filter=sub_filter,
                cms=der,
                signed_content=pdf[:gap_start] + pdf[gap_end : gap_end + tail],
                range_end=gap_end + tail,
            )
        )

    if not signatures:
        raise ValueError("el PDF no contiene ninguna firma")

    last_end = max(signature.range_end for signature in signatures)
    if last_end != len(pdf):
        raise ValueError(
            f"el PDF tiene {len(pdf) - last_end} bytes añadidos después de la última firma"
        )
    return signatures
