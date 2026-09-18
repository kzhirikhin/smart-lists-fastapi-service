"""Live-проверка production-функции Vertex AI на синтетических данных.

Токен gcloud живёт только в памяти процесса. Скрипт не меняет production client:
он заменяет его лишь в собственном процессе, чтобы вызвать тот же get_insight.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from google import genai
from google.oauth2.credentials import Credentials

from app.models.insights import ListItem, NotesMeta, ResponseLanguage, SubItem
from app.services import ai

PROJECT = "project-5b7c1bd1-572b-410d-826"
LOCATION = "global"
LANGUAGE_CASES: tuple[tuple[ResponseLanguage, str, str], ...] = (
    ("ru", "Проверка языка:", "Начни ответ точной фразой «Проверка языка:» и кратко расставь приоритеты."),
    ("en", "Language check:", "Start the answer with the exact phrase 'Language check:' and briefly prioritize the work."),
    ("vi", "Kiểm tra ngôn ngữ:", "Hãy bắt đầu bằng đúng cụm từ “Kiểm tra ngôn ngữ:” và ưu tiên ngắn gọn công việc."),
    ("ja", "言語確認：", "回答を必ず「言語確認：」で始め、作業の優先順位を簡潔に説明してください。"),
)


def _token() -> str:
    return subprocess.run(
        ["gcloud.cmd", "auth", "print-access-token"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _base_items() -> list[ListItem]:
    return [
        ListItem(name="Prepare release", is_completed=False, sub_items=[
            SubItem(name="Run tests", is_completed=True),
            SubItem(name="Review rollback", is_completed=False),
        ]),
        ListItem(name="Update documentation", is_completed=False),
    ]


def _peak_items() -> list[ListItem]:
    items: list[ListItem] = []
    for index in range(1, 51):
        note = None
        if index <= 10:
            seed = f"Task {index} depends on task {index + 1}; task {index + 2} conflicts with that decision. "
            note = (seed * 20)[:800]
        items.append(ListItem(
            name=f"Task {index}: cross-linked release requirement",
            is_completed=index % 7 == 0,
            note=note,
            sub_items=[
                SubItem(name=f"Validate dependency {index + 1}", is_completed=index % 3 == 0),
                SubItem(name=f"Resolve conflict {index + 2}", is_completed=index % 5 == 0),
            ],
        ))
    return items


async def _invoke(
    case_id: str,
    language: ResponseLanguage,
    user_message: str,
    items: list[ListItem],
    list_note: str | None = None,
    groups: list[str] | None = None,
    marker: str | None = None,
) -> dict[str, object]:
    started = time.perf_counter()
    text = await ai.get_insight(
        title="Synthetic stage 7 verification",
        items=items,
        groups=groups or [],
        user_message=user_message,
        list_note=list_note,
        notes_meta=NotesMeta(
            list_note_included=list_note is not None,
            included_item_notes=sum(
                entry.note is not None
                for item in items
                for entry in (item, *item.sub_items)
            ),
            omitted_item_notes=0,
        ),
        response_language=language,
    )
    latency = time.perf_counter() - started
    marker_ok = marker is None or marker in text[:120]
    if not marker_ok:
        raise RuntimeError(f"{case_id}: required language marker is absent")
    return {
        "case": case_id,
        "language": language,
        "latencySeconds": round(latency, 3),
        "responseChars": len(text),
        "responseSha256": hashlib.sha256(text.encode()).hexdigest(),
        "markerPassed": marker_ok,
    }


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    token = _token()
    ai.client = genai.Client(
        vertexai=True,
        project=PROJECT,
        location=LOCATION,
        credentials=Credentials(token),
    )

    results = []
    for language, marker, message in LANGUAGE_CASES:
        results.append(await _invoke(
            f"language-{language}", language, message, _base_items(), marker=marker
        ))

    peak_items = _peak_items()
    matrix = " ".join(f"Task {i}->{i + 1}; {i + 2} overrides {i}." for i in range(1, 51))
    results.append(await _invoke(
        "peak-cross-references",
        "ru",
        "Проанализируй критический путь, противоречия и следующие действия.",
        peak_items,
        list_note=(matrix * 8)[:4000],
        groups=[f"Group {i}" for i in range(1, 21)],
    ))

    report = {
        "generatedAt": datetime.now(UTC).isoformat(),
        "project": PROJECT,
        "location": LOCATION,
        "model": ai.MODEL,
        "credentialMode": "ephemeral-gcloud-user-token; runtime impersonation unavailable",
        "syntheticDataOnly": True,
        "results": results,
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())