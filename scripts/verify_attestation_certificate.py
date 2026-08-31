"""Проверка GitHub/Sigstore claims из X.509 уже верифицированной attestation."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
from pathlib import Path
from typing import Iterator


CLAIM_OIDS = {
    "runner": "1.3.6.1.4.1.57264.1.11",
    "repository_id": "1.3.6.1.4.1.57264.1.15",
    "event": "1.3.6.1.4.1.57264.1.20",
    "environment": "1.3.6.1.4.1.57264.1.23",
}


class CertificateError(ValueError):
    """Сертификат или verification result не соответствует контракту."""


def _read_tlv(data: bytes, offset: int, limit: int) -> tuple[int, int, int, int]:
    if offset >= limit:
        raise CertificateError("неожиданный конец DER")

    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise CertificateError("high-tag-number DER не поддерживается")
    if offset >= limit:
        raise CertificateError("у DER-элемента нет длины")

    first_length = data[offset]
    offset += 1
    if first_length < 0x80:
        length = first_length
    else:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 4 or offset + length_bytes > limit:
            raise CertificateError("некорректная DER-длина")
        if data[offset] == 0:
            raise CertificateError("DER-длина закодирована не минимально")
        length = int.from_bytes(data[offset : offset + length_bytes], "big")
        if length < 0x80:
            raise CertificateError("DER-длина должна использовать короткую форму")
        offset += length_bytes

    end = offset + length
    if end > limit:
        raise CertificateError("DER-элемент выходит за границы сертификата")
    return tag, offset, end, end


def _children(data: bytes, start: int, end: int) -> Iterator[tuple[int, int, int]]:
    cursor = start
    while cursor < end:
        tag, value_start, value_end, cursor = _read_tlv(data, cursor, end)
        yield tag, value_start, value_end
    if cursor != end:
        raise CertificateError("границы DER-контейнера не совпали")


def _encode_oid(oid: str) -> bytes:
    try:
        parts = [int(part) for part in oid.split(".")]
    except ValueError as exc:
        raise CertificateError(f"некорректный OID: {oid}") from exc
    if len(parts) < 2 or parts[0] not in (0, 1, 2):
        raise CertificateError(f"некорректный OID: {oid}")
    if parts[0] < 2 and not 0 <= parts[1] <= 39:
        raise CertificateError(f"некорректный OID: {oid}")

    values = [40 * parts[0] + parts[1], *parts[2:]]
    encoded = bytearray()
    for value in values:
        if value < 0:
            raise CertificateError(f"некорректный OID: {oid}")
        octets = [value & 0x7F]
        value >>= 7
        while value:
            octets.append(0x80 | (value & 0x7F))
            value >>= 7
        encoded.extend(reversed(octets))
    return bytes(encoded)


def extract_claims(certificate: bytes) -> dict[str, str]:
    """Извлекает ровно по одному DER UTF8String для обязательных Fulcio OID."""

    expected = {_encode_oid(oid): name for name, oid in CLAIM_OIDS.items()}
    found: dict[str, list[str]] = {name: [] for name in CLAIM_OIDS}

    def walk(tag: int, start: int, end: int) -> None:
        if tag == 0x30:  # SEQUENCE; X.509 Extension тоже является SEQUENCE.
            items = list(_children(certificate, start, end))
            if len(items) in (2, 3) and items[0][0] == 0x06:
                oid_bytes = certificate[items[0][1] : items[0][2]]
                name = expected.get(oid_bytes)
                value_item = items[-1]
                if name is not None and value_item[0] == 0x04:
                    inner = list(_children(certificate, value_item[1], value_item[2]))
                    if len(inner) != 1 or inner[0][0] != 0x0C:
                        raise CertificateError(
                            f"claim {name} не является DER UTF8String"
                        )
                    raw = certificate[inner[0][1] : inner[0][2]]
                    try:
                        found[name].append(raw.decode("utf-8", errors="strict"))
                    except UnicodeDecodeError as exc:
                        raise CertificateError(f"claim {name} не UTF-8") from exc

        if tag & 0x20:  # constructed SEQUENCE или context-specific container.
            for child_tag, child_start, child_end in _children(
                certificate, start, end
            ):
                walk(child_tag, child_start, child_end)

    tag, start, end, cursor = _read_tlv(certificate, 0, len(certificate))
    if tag != 0x30 or cursor != len(certificate):
        raise CertificateError("X.509 certificate не является одним DER SEQUENCE")
    walk(tag, start, end)

    claims: dict[str, str] = {}
    for name, values in found.items():
        if len(values) != 1:
            raise CertificateError(
                f"ожидался ровно один claim {name}, найдено: {len(values)}"
            )
        claims[name] = values[0]
    return claims


def verify_file(path: Path, expected: dict[str, str]) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertificateError("verification result не является читаемым JSON") from exc

    if not isinstance(document, list) or len(document) != 1:
        raise CertificateError("ожидался ровно один verification result")
    try:
        raw_bytes = document[0]["attestation"]["bundle"]["verificationMaterial"][
            "certificate"
        ]["rawBytes"]
    except (KeyError, TypeError) as exc:
        raise CertificateError("в verification result нет X.509 certificate") from exc
    if not isinstance(raw_bytes, str) or not raw_bytes:
        raise CertificateError("X.509 certificate пуст или имеет неверный тип")
    try:
        certificate = base64.b64decode(raw_bytes, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CertificateError("X.509 certificate не является строгим base64") from exc

    actual = extract_claims(certificate)
    mismatches = [
        f"{name}: ожидалось {value!r}, получено {actual[name]!r}"
        for name, value in expected.items()
        if actual[name] != value
    ]
    if mismatches:
        raise CertificateError("; ".join(mismatches))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verification", required=True, type=Path)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--runner", required=True)
    parser.add_argument("--repository-id", required=True)
    args = parser.parse_args()

    try:
        verify_file(
            args.verification,
            {
                "environment": args.environment,
                "event": args.event,
                "runner": args.runner,
                "repository_id": args.repository_id,
            },
        )
    except CertificateError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
