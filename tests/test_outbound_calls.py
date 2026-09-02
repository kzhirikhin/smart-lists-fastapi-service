"""Полнота контроля исходящих запросов сервиса (A56).

Зачем. SSRF в Cloud Run стоит дороже, чем в обычном приложении: metadata-сервер
отдаёт identity сервиса, а выключить или отфильтровать его нечем — link-local
адрес не проходит через VPC egress, и аналога `HttpEndpoint=disabled` из EC2 у
Cloud Run нет. Барьер поэтому держится целиком кодом: адрес каждого исходящего
запроса — константа, и ни один не выводится из данных или окружения.

До 2026-09-01 это утверждение закрепляли адреса существующих вызовов: точный URL
metadata-сервера с его параметрами и заголовком, и `base_url` клиента Anthropic
вместе с контрольным тестом, что механизм подмены жив. Само «ровно три» при этом
не проверялось ничем — четвёртый вызов с адресом из окружения прогон бы не
покрасил, а «проверено чтением кода» устаревает с первым же коммитом.

Форма проверки повторяет `TestActionPins` и `outbound-requests.test.ts` в
основном репозитории: набор берётся обходом `app`, а не списком, который надо не
забыть пополнить. Новый сетевой вызов обязан появиться в allowlist с причиной,
то есть стать осознанным решением, а не побочным следствием правки.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = REPO_ROOT / "app"

# Способы уйти наружу. Список закрывает не «все мыслимые», а все достижимые
# здесь: в `requirements.in` нет ни одного http-клиента помимо `requests`,
# который тянет сам google-auth, поэтому остаются эти вызовы и импорт нового.
OUTBOUND = (
    ("requests", re.compile(r"\brequests\.(?:get|post|put|patch|delete|head|request|Session)\s*\(")),
    ("httpx", re.compile(r"\bhttpx\.(?:AsyncClient|Client|get|post|request|stream)\s*\(")),
    ("urllib", re.compile(r"\burllib\.request\b|\burlopen\s*\(")),
    ("aiohttp", re.compile(r"\baiohttp\.")),
    ("socket", re.compile(r"\bsocket\.(?:socket|create_connection)\s*\(")),
    ("anthropic-client", re.compile(r"\banthropic\.(?:Async)?Anthropic\w*\s*\(")),
    ("google-transport", re.compile(r"\bgoogle_requests\.Request\s*\(")),
    ("google-id-token", re.compile(r"\bverify_oauth2_token\s*\(")),
)

# Модули, которым исходящий запрос разрешён, и почему. Пустая причина
# недопустима: смысл allowlist в объяснении, а не в разрешении.
ALLOWED: dict[str, str] = {
    "app/core/anthropic_auth.py": (
        "metadata-сервер GCP: адрес и params — константы, обязателен заголовок "
        "Metadata-Flavor; выдаёт ID-токен личности сервиса"
    ),
    "app/core/caller_auth.py": (
        "JWKS Google при проверке токена вызывающего; verify_oauth2_token не "
        "читает jku из самого токена"
    ),
    "app/services/ai.py": (
        "клиент Anthropic с явным base_url, поэтому ANTHROPIC_BASE_URL его не "
        "двигает (см. test_anthropic_auth)"
    ),
}


def _sources() -> list[tuple[str, str]]:
    return sorted(
        (
            path.relative_to(REPO_ROOT).as_posix(),
            path.read_text(encoding="utf-8"),
        )
        for path in APP_DIR.rglob("*.py")
    )


def _outbound_in(source: str) -> list[str]:
    return [name for name, pattern in OUTBOUND if pattern.search(source)]


class TestOutboundCalls:
    """Ни один исходящий адрес не приходит из данных или окружения."""

    def test_sources_are_visible(self) -> None:
        # Пустой набор сделал бы все проверки ниже бессмысленно зелёными.
        sources = _sources()
        names = [name for name, _ in sources]
        assert len(sources) >= 10
        assert "app/services/ai.py" in names
        assert "app/main.py" in names

    def test_detector_matches_real_calls(self) -> None:
        assert _outbound_in("response = requests.get(URL, timeout=5)") == ["requests"]
        assert _outbound_in("async with httpx.AsyncClient() as c: ...") == ["httpx"]
        assert _outbound_in("import aiohttp\naiohttp.ClientSession()") == ["aiohttp"]
        assert _outbound_in("sock = socket.create_connection((host, 443))") == ["socket"]

    def test_detector_ignores_similar_names(self) -> None:
        # Имя переменной или поля не должно попадать в allowlist: иначе он
        # разрастётся и перестанет означать «здесь действительно ходят наружу».
        assert _outbound_in("requests_total += 1") == []
        assert _outbound_in("from app.core.config import settings") == []
        assert _outbound_in("def build_socket_name(prefix: str) -> str: ...") == []

    def test_no_outbound_call_outside_allowlist(self) -> None:
        unexplained = [
            f"{name}: {', '.join(found)}"
            for name, body in _sources()
            if (found := _outbound_in(body)) and name not in ALLOWED
        ]

        assert unexplained == []

    def test_allowlist_has_no_stale_entries(self) -> None:
        # Иначе allowlist копит мёртвые строки и перестаёт быть описанием того,
        # где сервис действительно выходит в сеть.
        bodies = dict(_sources())
        stale = [
            name
            for name in ALLOWED
            if name not in bodies or not _outbound_in(bodies[name])
        ]

        assert stale == []

    def test_every_exception_carries_a_reason(self) -> None:
        for name, reason in ALLOWED.items():
            assert reason.strip(), name

    def test_anthropic_client_pins_its_base_url(self) -> None:
        # Связка та же, что у A68 в основном репозитории: адрес обязан
        # оставаться заданным кодом. Поведение — что переменная окружения не
        # двигает клиент — закреплено в test_anthropic_auth.
        body = (REPO_ROOT / "app" / "services" / "ai.py").read_text(encoding="utf-8")
        assert "base_url=" in body
