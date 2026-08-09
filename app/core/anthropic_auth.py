"""
Доступ к Anthropic без ключа API.

Сервис предъявляет не секрет, а подписанный Google ID-токен собственной
личности в Cloud Run, и обменивает его на access-токен со сроком жизни десять
минут. Разница не в удобстве: ключ API — предъявительский секрет, который
работает у любого, кто его увидел, а этот токен выдаётся только тому, кто
способен получить подпись Google изнутри контейнера. Утечка конфигурации
сервиса доступа к Anthropic больше не даёт: все четыре идентификатора ниже
несекретны.

Токен берём у metadata-сервера напрямую, а не через `fetch_id_token` из
`google-auth`. Нужен `format=full`: без него в токене нет claim `email`, а
правило федерации на стороне Anthropic сверяет именно его вместе с `sub`.
Явный параметр в запросе виден в коде и не зависит от умолчаний библиотеки,
которые могут измениться при обновлении зависимости.
"""

import requests
from anthropic import WorkloadIdentityCredentials

from app.core.config import settings

# Адрес metadata-сервера постоянен и доступен только изнутри workload'а Google
# Cloud: снаружи имя не резолвится, поэтому подделать выдачу токена из другой
# среды нельзя.
_IDENTITY_URL = (
    "http://metadata.google.internal/computeMetadata/v1"
    "/instance/service-accounts/default/identity"
)

# Anthropic принимает токен только с этим audience и сверяет его в правиле.
_AUDIENCE = "https://api.anthropic.com"

# Metadata-сервер локален, и медленный ответ означает неисправность, а не
# нагрузку: ждать дольше незачем.
_TIMEOUT_SECONDS = 5


def fetch_identity_token() -> str:
    """Возвращает Google ID-токен личности сервиса.

    Вызывается SDK при каждом обмене, то есть примерно раз в десять минут, а
    не на каждый запрос: обменянный токен живёт в кеше клиента.
    """
    response = requests.get(
        _IDENTITY_URL,
        params={"audience": _AUDIENCE, "format": "full"},
        headers={"Metadata-Flavor": "Google"},
        timeout=_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.text


def build_credentials() -> WorkloadIdentityCredentials:
    """Собирает поставщик access-токенов Anthropic.

    `workspace_id` указан явно, хотя сервер выбрал бы единственный доступный
    правилу workspace сам. Неявный выбор перестанет работать в тот день, когда
    правило получит второй workspace, — и сломается это не при изменении
    правила, а при следующем запросе инсайта.
    """
    return WorkloadIdentityCredentials(
        identity_token_provider=fetch_identity_token,
        federation_rule_id=settings.anthropic_federation_rule_id,
        organization_id=settings.anthropic_organization_id,
        service_account_id=settings.anthropic_service_account_id,
        workspace_id=settings.anthropic_workspace_id,
    )
