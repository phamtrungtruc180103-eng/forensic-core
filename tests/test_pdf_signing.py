from __future__ import annotations

import os
import unittest
from io import BytesIO
from pathlib import Path

from pyhanko.keys import load_certs_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import KeyUsageConstraints, validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from backend.main import build_report_pdf
from backend.pdf_signing import certificate_common_name, sign_pdf_pades


class PDFSigningTest(unittest.TestCase):
    def test_fabric_identity_creates_pades_signature(self) -> None:
        configured_msp = os.getenv("TEST_PDF_MSP_PATH")
        if not configured_msp:
            self.skipTest("TEST_PDF_MSP_PATH is not configured")
        msp_path = Path(configured_msp)
        if not msp_path.is_dir():
            self.skipTest("Fabric Admin MSP is unavailable")
        report = {
            "report": {"reportID": "TEST", "createdBy": "tester", "createdAt": "2026-10-15T00:00:00Z", "timezone": "UTC"},
            "project": {}, "evidence": [], "hashChecks": [], "custody": [],
            "conclusion": "ALL_MATCH", "limitations": "test", "generatedAt": "2026-10-15T00:00:00Z",
        }
        unsigned = build_report_pdf(report)

        signed = sign_pdf_pades(unsigned, msp_path, "AcceptanceSignature", certificate_common_name(msp_path), "Acceptance test")

        self.assertGreater(len(signed), len(unsigned))
        self.assertIn(b"/ETSI.CAdES.detached", signed)
        self.assertIn(b"/ByteRange", signed)
        trust_roots = list(load_certs_from_pemder([str(path) for path in (msp_path / "cacerts").glob("*")]))
        reader = PdfFileReader(BytesIO(signed))
        status = validate_pdf_signature(
            reader.embedded_signatures[0],
            signer_validation_context=ValidationContext(trust_roots=trust_roots, allow_fetching=False),
            key_usage_settings=KeyUsageConstraints(key_usage={"digital_signature"}),
        )
        self.assertTrue(status.intact)
        self.assertTrue(status.valid)


if __name__ == "__main__":
    unittest.main()
