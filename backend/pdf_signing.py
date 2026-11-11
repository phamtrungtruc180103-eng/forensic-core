from __future__ import annotations

from io import BytesIO
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers


def _single_file(directory: Path, label: str) -> Path:
    files = [path for path in directory.iterdir() if path.is_file()]
    if len(files) != 1:
        raise RuntimeError(f"Expected exactly one {label} file in {directory}, found {len(files)}")
    return files[0]


def sign_pdf_pades(
    pdf_bytes: bytes,
    msp_path: Path,
    field_name: str,
    signer_name: str,
    reason: str,
) -> bytes:
    key_file = _single_file(msp_path / "keystore", "private key")
    cert_file = _single_file(msp_path / "signcerts", "signing certificate")
    ca_files = sorted((msp_path / "cacerts").glob("*"))
    signer = signers.SimpleSigner.load(
        key_file=str(key_file),
        cert_file=str(cert_file),
        ca_chain_files=[str(path) for path in ca_files],
        key_passphrase=None,
    )
    if signer is None:
        raise RuntimeError("Unable to load Fabric signing identity for PDF signature")
    source = BytesIO(pdf_bytes)
    output = BytesIO()
    writer = IncrementalPdfFileWriter(source)
    metadata = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm="sha256",
        subfilter=fields.SigSeedSubFilter.PADES,
        name=signer_name,
        reason=reason,
        location="Forensic Core / Hyperledger Fabric",
    )
    signers.sign_pdf(
        writer,
        signature_meta=metadata,
        signer=signer,
        new_field_spec=fields.SigFieldSpec(sig_field_name=field_name),
        output=output,
    )
    return output.getvalue()


def certificate_common_name(msp_path: Path) -> str:
    cert_file = _single_file(msp_path / "signcerts", "signing certificate")
    certificate = x509.load_pem_x509_certificate(cert_file.read_bytes())
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return names[0].value if names else certificate.subject.rfc4514_string()
