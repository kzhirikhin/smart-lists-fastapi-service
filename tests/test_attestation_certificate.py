from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from scripts.verify_attestation_certificate import (
    CLAIM_OIDS,
    CertificateError,
    _encode_oid,
    extract_claims,
    verify_file,
)


EXPECTED = {
    "environment": "production",
    "event": "push",
    "runner": "github-hosted",
    "repository_id": "1199475908",
}


def _length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _certificate(claims: dict[str, list[str]]) -> bytes:
    extensions = []
    for name, values in claims.items():
        for value in values:
            extension = _tlv(0x06, _encode_oid(CLAIM_OIDS[name])) + _tlv(
                0x04, _tlv(0x0C, value.encode("utf-8"))
            )
            extensions.append(_tlv(0x30, extension))
    # Минимальное дерево достаточно для теста DER-обхода: настоящий X.509 имеет
    # те же Extension SEQUENCE внутри constructed context-specific контейнера.
    return _tlv(0x30, _tlv(0xA3, _tlv(0x30, b"".join(extensions))))


def _write_result(tmp_path: Path, certificate: bytes) -> Path:
    path = tmp_path / "verification.json"
    path.write_text(
        json.dumps(
            [
                {
                    "attestation": {
                        "bundle": {
                            "verificationMaterial": {
                                "certificate": {
                                    "rawBytes": base64.b64encode(certificate).decode()
                                }
                            }
                        }
                    }
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_extracts_exact_fulcio_claims() -> None:
    certificate = _certificate({name: [value] for name, value in EXPECTED.items()})
    assert extract_claims(certificate) == EXPECTED


@pytest.mark.parametrize("missing", EXPECTED)
def test_missing_claim_fails(missing: str) -> None:
    claims = {name: [value] for name, value in EXPECTED.items() if name != missing}
    with pytest.raises(CertificateError, match=f"claim {missing}"):
        extract_claims(_certificate(claims))


def test_duplicate_claim_fails() -> None:
    claims = {name: [value] for name, value in EXPECTED.items()}
    claims["environment"].append("staging")
    with pytest.raises(CertificateError, match="ровно один claim environment"):
        extract_claims(_certificate(claims))


def test_wrong_environment_fails(tmp_path: Path) -> None:
    actual = {**EXPECTED, "environment": "staging"}
    result = _write_result(
        tmp_path,
        _certificate({name: [value] for name, value in actual.items()}),
    )
    with pytest.raises(CertificateError, match="environment"):
        verify_file(result, EXPECTED)


def test_exact_verification_result_passes(tmp_path: Path) -> None:
    result = _write_result(
        tmp_path,
        _certificate({name: [value] for name, value in EXPECTED.items()}),
    )
    verify_file(result, EXPECTED)
