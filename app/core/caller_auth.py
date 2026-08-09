"""
Проверка того, кто нас позвал.

Способов два, и они сосуществуют только на время перехода.

1. **Google ID-токен** в заголовке `Authorization`. Cloud Run проверяет его сам,
   до того как запрос дойдёт сюда, — но проверяет право звать, а не личность
   вызывающего с точки зрения приложения. Мы проверяем его повторно и
   независимо: подпись, `aud` и `email`. Это осмысленно ровно потому, что
   однажды уже случилось: `run.invoker` был выдан `allUsers`, и тогда платформа
   не проверяла ничего. При такой ошибке единственным барьером остаётся эта
   проверка, и подделать её нельзя — подпись выдаёт Google.

   Токен доходит сюда целым только из заголовка `Authorization`. У
   `X-Serverless-Authorization` Cloud Run вырезает подпись перед передачей в
   контейнер, заменяя её на `SIGNATURE_REMOVED_BY_GOOGLE`; claims читаются, но
   проверить их подлинность уже нельзя. Проверено экспериментом 2026-08-09.

2. **Shared secret** — прежний способ. Остаётся, пока вызывающая сторона не
   переключится на токен, и удаляется сразу после.

Общий принцип: любая ошибка означает отказ. Ни одна ветка не может завершиться
«ну ладно, пропустим».
"""

import base64
import binascii
import hmac
import json
import logging
from typing import Optional

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token

from app.core.config import settings

logger = logging.getLogger(__name__)

# Транспорт держит кеш публичных ключей Google, поэтому создаётся один раз.
# Следствие, которое стоит знать: при холодном старте первая проверка ходит в
# сеть за сертификатами. Недоступность этого эндпоинта означает отказ в
# обслуживании, а не пропуск непроверенных запросов.
_transport = google_requests.Request()


def _extract_bearer(authorization: str) -> Optional[str]:
    """Возвращает токен из `Bearer <token>` либо None."""
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None
    token = authorization[len(prefix):].strip()
    return token or None


def _allowed_audiences() -> list[str]:
    """Допустимые значения `aud`, разделённые запятой.

    Список, а не одна строка: у сервиса Cloud Run адресов бывает несколько —
    исторический `<service>-<hash>-<region>.a.run.app` и современный
    `<service>-<project-number>.<region>.run.app`, — и оба ведут на него.
    Вызывающая сторона выпускает токен под тот адрес, который у неё настроен,
    и жёсткая привязка к одному варианту сломалась бы при смене адреса,
    а не при смене прав. Все значения указывают на один и тот же сервис,
    поэтому проверка ничего не теряет.
    """
    raw = settings.service_audience or ""
    return [item.strip() for item in raw.split(",") if item.strip()]


def _unverified_audience(token: str) -> Optional[str]:
    """Достаёт `aud` из непроверенных claims — только для сообщения об ошибке.

    Значение непроверенное и решений по нему принимать нельзя: сюда попадают
    в том числе полностью поддельные токены. Оно годится ровно на одно —
    объяснить в логе, почему проверка не прошла.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1]
        padded = payload + "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(padded)).get("aud")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


def _matches_shared_secret(authorization: str) -> bool:
    """Сравнение за постоянное время, устойчивое к не-ASCII заголовку.

    `hmac.compare_digest` на строках требует ASCII и иначе бросает TypeError.
    Заголовок приходит от клиента, поэтому не-ASCII там — вопрос времени;
    без перехвата это был бы необработанный 500 на пути до аутентификации.
    """
    expected = f"Bearer {settings.service_secret}"
    try:
        return hmac.compare_digest(authorization, expected)
    except TypeError:
        return False


def _is_valid_google_id_token(authorization: str) -> bool:
    """Проверяет подпись, срок, `aud` и то, что вызывающий — ожидаемый SA."""
    audiences = _allowed_audiences()
    if not settings.expected_caller_sa or not audiences:
        return False

    token = _extract_bearer(authorization)
    if token is None:
        return False

    try:
        # Проверяет подпись публичными ключами Google, `iss`, `exp` и `aud`.
        claims = google_id_token.verify_oauth2_token(
            token, _transport, audience=audiences
        )
    except Exception as exc:
        # Только тип исключения: текст может содержать фрагменты токена.
        # Отдельно — audience из непроверенных claims. Это публичный адрес
        # сервиса, не секрет, а расхождение в нём даёт неотличимый от прочих
        # отказ: без этой строки «не тот aud» и «подделка» выглядят одинаково.
        logger.warning(
            "ID-токен отклонён: %s (audience в токене: %s, ожидались: %s)",
            type(exc).__name__,
            _unverified_audience(token),
            audiences,
        )
        return False

    if not claims.get("email_verified", False):
        logger.warning("ID-токен без подтверждённого email")
        return False

    email = claims.get("email")
    if email != settings.expected_caller_sa:
        # Email service account не секрет и нужен для разбора: без него
        # «токен валиден, но не тот» неотличимо от «токен невалиден».
        logger.warning("ID-токен выпущен другому вызывающему: %s", email)
        return False

    return True


def is_authorized(authorization: str) -> bool:
    """Пускаем, если сходится shared secret либо валиден Google ID-токен.

    Секрет проверяется первым: сравнение дешёвое и не ходит в сеть, а на время
    перехода это основной путь.
    """
    if _matches_shared_secret(authorization):
        return True
    return _is_valid_google_id_token(authorization)
