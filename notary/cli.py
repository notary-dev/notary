"""Command Line Interface (CLI) entry point for notary."""

import argparse
import sys
from typing import List, Optional


def build_parser() -> argparse.ArgumentParser:
    """Construct argument parser adhering to the assignment requirements."""
    parser = argparse.ArgumentParser(
        prog="notary",
        description="Notary — Herramienta de firma electrónica CAdES-T con DNIe y sellos de tiempo RFC 3161.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles:")

    # Command: info
    parser_info = subparsers.add_parser(
        "info",
        help="Muestra los lectores, el DNIe, sus certificados y el estado del PIN.",
    )
    parser_info.add_argument(
        "--module",
        metavar="RUTA",
        default=None,
        help="Ruta al módulo PKCS#11 (.dll o .so). Si se omite, se intenta detectar automáticamente.",
    )

    # Command: sign
    parser_sign = subparsers.add_parser(
        "sign",
        help="Firma un archivo y añade un sello de tiempo RFC 3161.",
    )
    parser_sign.add_argument("file", help="Ruta al archivo a firmar.")
    parser_sign.add_argument(
        "--format",
        choices=["detached", "attached", "pades"],
        default="detached",
        help="Formato: detached (separada), attached (con el contenido incluido) o pades (firma dentro de un PDF). Por defecto: detached.",
    )
    parser_sign.add_argument(
        "--tsa",
        nargs="+",
        metavar="URL",
        default=None,
        help="Direcciones de autoridades de sellado de tiempo RFC 3161, en orden de preferencia.",
    )
    parser_sign.add_argument(
        "--out",
        metavar="ARCHIVO",
        default=None,
        help="Ruta del archivo de firma .csig. Por defecto: <archivo>.csig.",
    )
    parser_sign.add_argument(
        "--key",
        metavar="CLAVE_PEM",
        default=None,
        help="Ruta de la clave privada PEM para usar el firmante software de desarrollo.",
    )
    parser_sign.add_argument(
        "--cert",
        metavar="CERT_PEM",
        default=None,
        help="Ruta del certificado X.509 PEM asociado a la clave privada.",
    )
    parser_sign.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Solo desarrollo: firma sin sello de tiempo (CAdES-BES). No sirve como prueba de cuándo se firmó.",
    )
    parser_sign.add_argument(
        "--module",
        metavar="RUTA",
        default=None,
        help="Ruta al módulo PKCS#11 para firmar con el DNIe. Si se omite, se intenta detectar automáticamente.",
    )

    parser_sign.add_argument(
        "--ltv",
        action="store_true",
        help="Incrusta en la firma la cadena de certificados y una respuesta OCSP (CAdES-LT) para verificarla años después y sin red.",
    )
    parser_sign.add_argument(
        "--chain",
        nargs="+",
        metavar="CERTIFICADO",
        default=None,
        help="Certificados emisores (PEM o DER) para --ltv. Los que falten se descargan de la AIA del certificado.",
    )

    # Command: pin-guard
    parser_guard = subparsers.add_parser(
        "pin-guard",
        help="Muestra, fija o reinicia el contador local de PIN incorrectos del DNIe (no pide el PIN).",
    )
    parser_guard.add_argument("--reset", action="store_true", help="Reinicia el contador a 0 (tras un PIN correcto fuera de notary o tras pasar por un PAD).")
    parser_guard.add_argument("--set", type=int, default=None, metavar="N", dest="set_failed", help="Fija el contador a N fallos (0-3), si sabes cuántos se han gastado.")
    parser_guard.add_argument("--module", metavar="RUTA", default=None, help="Ruta al módulo PKCS#11.")

    # Command: cosign
    parser_cosign = subparsers.add_parser(
        "cosign",
        help="Añade una segunda firma en paralelo (otro firmante) a un .csig existente.",
    )
    parser_cosign.add_argument("proof", help="Ruta del .csig al que se añade la firma.")
    parser_cosign.add_argument("file", help="Documento firmado (el mismo que en la primera firma).")
    parser_cosign.add_argument("--tsa", nargs="+", metavar="URL", default=None, help="TSA, en orden de preferencia.")
    parser_cosign.add_argument("--out", metavar="ARCHIVO", default=None, help="Salida. Por defecto: <prueba>.multi.csig (no sobrescribe la original).")
    parser_cosign.add_argument("--key", metavar="CLAVE_PEM", default=None, help="Clave privada PEM del firmante software.")
    parser_cosign.add_argument("--cert", metavar="CERT_PEM", default=None, help="Certificado PEM del firmante software.")
    parser_cosign.add_argument("--module", metavar="RUTA", default=None, help="Módulo PKCS#11 para firmar con el DNIe.")
    parser_cosign.add_argument("--ltv", action="store_true", help="Incrusta cadena y OCSP del nuevo firmante (CAdES-LT).")
    parser_cosign.add_argument("--chain", nargs="+", metavar="CERTIFICADO", default=None, help="Certificados emisores para --ltv.")

    # Command: verify
    parser_verify = subparsers.add_parser(
        "verify",
        help="Verifica un archivo de firma digital .csig.",
    )
    parser_verify.add_argument("proof", help="Ruta del archivo .csig que contiene la firma.")
    parser_verify.add_argument(
        "--content",
        metavar="ARCHIVO",
        default=None,
        help="Ruta del archivo original. Es obligatorio si la firma está separada (detached).",
    )
    parser_verify.add_argument(
        "--trust",
        nargs="+",
        metavar="CERTIFICADO",
        default=None,
        help="Rutas de certificados raíz de confianza, en formato PEM o DER.",
    )
    parser_verify.add_argument(
        "--at",
        metavar="FECHA_HORA",
        default=None,
        help="Instante de evaluación, en formato ISO 8601 y zona horaria UTC.",
    )

    return parser


def main(args: Optional[List[str]] = None) -> int:
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 1

    if parsed_args.command == "info":
        from notary.info import run_info
        return run_info(custom_module=parsed_args.module)
    elif parsed_args.command == "sign":
        from notary.sign import run_sign
        return run_sign(
            parsed_args.file,
            fmt=parsed_args.format,
            tsa_urls=parsed_args.tsa,
            out=parsed_args.out,
            key=parsed_args.key,
            cert=parsed_args.cert,
            no_timestamp=parsed_args.no_timestamp,
            module=parsed_args.module,
            ltv=parsed_args.ltv,
            chain=parsed_args.chain,
        )
    elif parsed_args.command == "pin-guard":
        from notary.pin_guard import run_pin_guard
        return run_pin_guard(
            reset=parsed_args.reset, set_failed=parsed_args.set_failed, module=parsed_args.module
        )
    elif parsed_args.command == "cosign":
        from notary.sign import run_sign
        return run_sign(
            parsed_args.file,
            tsa_urls=parsed_args.tsa,
            out=parsed_args.out,
            key=parsed_args.key,
            cert=parsed_args.cert,
            module=parsed_args.module,
            ltv=parsed_args.ltv,
            chain=parsed_args.chain,
            base_proof=parsed_args.proof,
        )
    elif parsed_args.command == "verify":
        from notary.verify import run_verify
        return run_verify(
            parsed_args.proof,
            content=parsed_args.content,
            trust=parsed_args.trust,
            at=parsed_args.at,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
