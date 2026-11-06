"""Implementation of the 'notary info' command."""

import sys
from typing import Optional, Set
import PyKCS11
from asn1crypto import x509

from notary.pkcs11_utils import find_pkcs11_module, get_token_flags_description


def get_key_usage_names(cert: x509.Certificate) -> Set[str]:
    """Extract set of key usage strings from certificate if present."""
    try:
        ku_ext = cert.key_usage_value
        if ku_ext and ku_ext.native:
            return set(ku_ext.native)
    except Exception:
        pass
    return set()


def identify_certificate_role(cert: x509.Certificate, label: str) -> str:
    """Identify whether a certificate is for digital signature or authentication.
    
    Uses the KeyUsage bits documented for DNIe certificates, with the token label
    as a fallback when the extension does not identify the role:
    - Non-repudiation (content_commitment) -> CertFirmaDigital
    - Digital signature -> CertAutenticacion
    """
    usages = get_key_usage_names(cert)
    
    if "non_repudiation" in usages or "content_commitment" in usages:
        return "CERTIFICADO DE FIRMA DIGITAL (CertFirmaDigital)"
    elif "digital_signature" in usages:
        return "CERTIFICADO DE AUTENTICACIÓN (CertAutenticacion)"
    
    # Fallback to label if KeyUsage is absent or ambiguous
    if "firma" in label.lower():
        return "FIRMA DIGITAL (según etiqueta)"
    if "autentica" in label.lower():
        return "AUTENTICACIÓN (según etiqueta)"
    
    return "CERTIFICADO X.509"


def _to_bytes(val) -> bytes:
    """Safely convert PyKCS11 attribute value to bytes."""
    if isinstance(val, bytes):
        return val
    if isinstance(val, (list, tuple)):
        return bytes(val)
    if isinstance(val, str):
        return val.encode("latin1", errors="replace")
    return bytes(val)


def _to_str(val) -> str:
    """Safely convert PyKCS11 attribute value to a human readable string."""
    if isinstance(val, str):
        return val
    if isinstance(val, (bytes, bytearray)):
        return val.decode("utf-8", errors="replace")
    if isinstance(val, (list, tuple)):
        try:
            return bytes(val).decode("utf-8", errors="replace")
        except Exception:
            return "".join(chr(b) if isinstance(b, int) else str(b) for b in val)
    return str(val)


def run_info(custom_module: Optional[str] = None) -> int:
    """Execute the 'notary info' command."""
    print("=" * 70)
    print(" NOTARY INFO — Información de lectores y certificados PKCS#11")
    print("=" * 70)

    try:
        module_path = find_pkcs11_module(custom_module)
        print(f"[+] Se ha cargado el módulo PKCS#11: {module_path}")
    except FileNotFoundError as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1

    p11 = PyKCS11.PyKCS11Lib()
    try:
        p11.load(module_path)
    except Exception as e:
        print(f"[-] No se ha podido cargar la biblioteca PKCS#11 ({module_path}): {e}", file=sys.stderr)
        return 1

    try:
        all_slots = p11.getSlotList()
    except Exception as e:
        print(f"[-] No se ha podido consultar la lista de ranuras PKCS#11: {e}", file=sys.stderr)
        return 1

    if not all_slots:
        print(
            "[-] No se han encontrado ranuras PKCS#11 disponibles. Comprueba que el lector está "
            "conectado o, con el móvil, que DNIe Remote está abierto y vinculado."
        )
        return 1

    print(f"[+] Ranuras PKCS#11 detectadas: {len(all_slots)}")

    token_found = False
    inspection_failed = False
    for slot_idx, slot in enumerate(all_slots):
        try:
            slot_info = p11.getSlotInfo(slot)
            token_present = bool(slot_info.flags & PyKCS11.CKF_TOKEN_PRESENT)
            print(f"\n--- Ranura {slot_idx} (ID: 0x{slot:X}) ---")
            print(f"  Descripción del lector: {slot_info.slotDescription.strip()}")
            print(f"  Fabricante         : {slot_info.manufacturerID.strip()}")
            print(f"  Tarjeta insertada  : {'SÍ' if token_present else 'NO'}")

            if not token_present:
                continue

            token_found = True
            token_info = p11.getTokenInfo(slot)
            print(f"  Etiqueta del token : {token_info.label.strip()}")
            print(f"  Fabricante del token: {token_info.manufacturerID.strip()}")
            print(f"  Modelo del token   : {token_info.model.strip()}")
            print(f"  Número de serie    : {token_info.serialNumber.strip()}")

            # Show PIN security flags
            print("\n  [Estado de seguridad del PIN (flags PKCS#11)]:")
            flags = get_token_flags_description(token_info.flags)
            for flag_name, is_set in flags:
                flag_str = "ACTIVO" if is_set else "inactivo"
                if flag_name == "USER_PIN_FINAL_TRY" and is_set:
                    print(f"    [!] {flag_name}: ¡Atención! Solo queda un intento antes de que se bloquee el PIN.")
                elif flag_name == "USER_PIN_LOCKED" and is_set:
                    print(f"    [X] {flag_name}: El PIN está bloqueado. Acude a un Punto de Actualización del DNIe para desbloquearlo.")
                else:
                    print(f"    •  {flag_name:<30}: {flag_str}")

            # Open a public session WITHOUT login to read public certificates
            try:
                session = p11.openSession(slot)
            except PyKCS11.PyKCS11Error as e_sess:
                inspection_failed = True
                print(f"\n  [-] No se ha podido abrir una sesión con la tarjeta: {e_sess}")
                print("      Si usas el móvil como lector, comprueba que la aplicación esté activa y que el DNIe esté junto a la antena NFC.")
                continue

            try:
                cert_objects = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
                print(f"\n  [Certificados en la tarjeta: {len(cert_objects)}]")

                if not cert_objects:
                    inspection_failed = True
                    print("    (No se han encontrado certificados X.509.)")

                for c_idx, c_obj in enumerate(cert_objects, 1):
                    try:
                        attrs = session.getAttributeValue(c_obj, [
                            PyKCS11.CKA_VALUE,
                            PyKCS11.CKA_LABEL,
                            PyKCS11.CKA_ID
                        ])
                        cert_der = _to_bytes(attrs[0])
                        label = _to_str(attrs[1]).strip() if attrs[1] else f"(Certificado #{c_idx})"
                        cert = x509.Certificate.load(cert_der)

                        role = identify_certificate_role(cert, label)
                        usages = get_key_usage_names(cert)

                        print(f"\n    Certificado #{c_idx}: {label}")
                        print("    --------------------------------------------------")
                        print(f"    Función / Rol      : {role}")
                        print(f"    Titular            : {cert.subject.human_friendly}")
                        print(f"    Emisor             : {cert.issuer.human_friendly}")
                        print(f"    Número de Serie    : 0x{cert.serial_number:X}")
                        print(f"    Válido desde (UTC) : {cert['tbs_certificate']['validity']['not_before'].native}")
                        print(f"    Válido hasta (UTC) : {cert['tbs_certificate']['validity']['not_after'].native}")
                        print(f"    Uso de clave       : {', '.join(sorted(usages)) if usages else 'No especificado'}")

                    except Exception as e_cert:
                        inspection_failed = True
                        print(f"    [-] No se ha podido leer el certificado #{c_idx}: {e_cert}")

            finally:
                session.closeSession()

        except Exception as e_slot:
            inspection_failed = True
            print(f"  [-] No se ha podido inspeccionar la ranura {slot}: {e_slot}")

    if not token_found:
        print("\n[!] No se ha detectado ningún DNIe conectado.")
        print("    Conecta el lector USB o inicia y empareja DNIe Remote con el móvil.")
        inspection_failed = True

    if inspection_failed:
        print("[!] El diagnóstico no se ha podido completar correctamente.")

    print("\n" + "=" * 70)
    if inspection_failed:
        return 1
    return 0

