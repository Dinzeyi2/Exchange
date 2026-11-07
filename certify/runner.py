"""Signed, reproducible distributed acceptance evidence. Never self-asserts bank go-live."""

import base64
import hashlib
import json
from pathlib import Path

from node.audit.store import now
from node.identity.crypto import canonical
from node.signer.backends import SoftwareSigner


def pdf(text):
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = ("BT /F1 11 Tf 40 780 Td (" + escaped + ") Tj ET").encode(
        "ascii", "replace"
    )
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length "
        + str(len(stream)).encode()
        + b" >>\nstream\n"
        + stream
        + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out.extend(str(i).encode() + b" 0 obj\n" + obj + b"\nendobj\n")
    xref = len(out)
    out.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode())
    out.extend(
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"
        + str(xref).encode()
        + b"\n%%EOF\n"
    )
    return bytes(out)


def run(output, deployment="processes"):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    import tempfile

    with tempfile.TemporaryDirectory(dir=output, prefix="acceptance-") as root:
        if deployment == "processes":
            from certify.distributed import run_processes

            result = run_processes(root)
        elif deployment == "containers":
            from certify.containers import run as run_containers

            result = run_containers(root)
        else:
            raise ValueError("deployment must be processes or containers")
    signer = SoftwareSigner.load_or_create(output / "evidence-signing-key.pem")
    source_root = Path(__file__).resolve().parents[1]
    inputs = {}
    for directory, pattern in [
        ("node", "*.py"),
        ("certify", "*.py"),
        ("protocol", "*.json"),
        ("ui/src", "*"),
        ("deploy", "Dockerfile"),
    ]:
        for source in sorted((source_root / directory).rglob(pattern)):
            if source.is_file():
                inputs[str(source.relative_to(source_root))] = hashlib.sha256(
                    source.read_bytes()
                ).hexdigest()
    for name in [
        "pyproject.toml",
        "uv.lock",
        "requirements.lock",
        "ui/package-lock.json",
    ]:
        source = source_root / name
        if source.exists():
            inputs[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    report = {
        "version": "0.2.0",
        "host_source_tree_sha256": hashlib.sha256(canonical(inputs)).hexdigest(),
        "scope": "distributed acceptance with controlled bank fixtures",
        "status": "distributed_acceptance_passed",
        "ts": now(),
        "result": result,
        "go_live_eligible": False,
        "unverified_bank_controls": [
            "real bank HSM sessions and key administration",
            "bank OIDC issuer, MFA and officer entitlement mapping",
            "approved legal document template",
            "bank payment-hub ISO scheme XSDs and genuine booked credits",
            "bank-specific loan-system adapter reconciliation",
            "bank deployment hardening, backup/restore and independent security review",
        ],
        "public_key": base64.b64encode(signer.public_key).decode(),
    }
    printable = pdf(
        "Exchange distributed acceptance: PASSED. Controlled fixtures; NOT bank go-live approval. See report.json for evidence."
    )
    (output / "report.pdf").write_bytes(printable)
    pdf_record = {
        "file": "report.pdf",
        "sha256": hashlib.sha256(printable).hexdigest(),
        "ts": report["ts"],
        "public_key": report["public_key"],
    }
    pdf_record["signature"] = signer.sign(pdf_record)
    (output / "report.pdf.sig.json").write_bytes(canonical(pdf_record))
    report["pdf_sha256"] = pdf_record["sha256"]
    report["signature"] = signer.sign(report)
    (output / "report.json").write_text(json.dumps(report, indent=2))
    return report
