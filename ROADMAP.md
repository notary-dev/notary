# Roadmap

Ideas for after the first public release, roughly in priority order. Nothing here is promised.

## 1. English by default
Today every CLI message, `--help` text, error and source comment is in Spanish.
- Add `notary/i18n.py` with a Spanish→English catalogue and a `t()` helper.
- English by default; Spanish with `--lang es` or `NOTARY_LANG=es`.
- Route `argparse` help, `print` calls and errors through `t()` (about 200 strings, mostly in `info`, `sign`, `verify`, `pin_guard`, `pkcs11_signer`).
- Tests: English as the default, plus a set with `--lang es` so the Spanish texts stay covered.
- Optional: translate code comments and docstrings, and the machine-readable verdict (`VEREDICTO` → `VERDICT`).

## 2. Project hygiene
- GitHub Actions: run the tests on Windows, Linux and macOS for Python 3.12+.
- Linting and typing (`ruff`, `mypy`), and a pre-commit config.
- Publish to PyPI (`pip install notary-dnie`), with a changelog and tagged releases.
- `SECURITY.md` (how to report a vulnerability) and `CONTRIBUTING.md`.

## 3. Features
- **PAdES-LT / LTA:** write the `/DSS` dictionary with chain and OCSP, and archive timestamps; allow `--ltv` with PAdES.
- **Visible PAdES signature** on a chosen page and position.
- **CAdES-LTA** (`archiveTimeStamp`) and nested countersignatures.
- **ECDSA** signers (the DNIe uses RSA, but other eIDs do not).
- **DocMDP** permissions, so later allowed changes (form filling) do not count as tampering.
- **Machine-readable output:** `--json` for `verify`, for use in scripts and CI.

## 4. Known problems
- DNIe Remote (phone as reader) fails at the PIN step; see "Known limitations" in `docs/DESIGN.md`.
- The PIN counter cannot see attempts made by other programs.

## Out of scope
`notary` is an educational implementation: it will not be audited or certified, and is not a replacement for AutoFirma or other qualified tools.
