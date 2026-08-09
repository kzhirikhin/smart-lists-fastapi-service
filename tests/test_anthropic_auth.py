from unittest.mock import MagicMock, patch

import anthropic
import pytest
import requests
from anthropic import WorkloadIdentityCredentials

from app.core import anthropic_auth


def make_metadata_response(text: str) -> MagicMock:
    """Ответ metadata-сервера: тело токена и успешный статус."""
    response = MagicMock()
    response.text = text
    response.raise_for_status = MagicMock()
    return response


def test_identity_token_requested_with_full_format():
    with patch("app.core.anthropic_auth.requests.get") as mock_get:
        mock_get.return_value = make_metadata_response("header.payload.signature")

        token = anthropic_auth.fetch_identity_token()

    assert token == "header.payload.signature"

    (url,) = mock_get.call_args.args
    assert url.startswith("http://metadata.google.internal/")

    kwargs = mock_get.call_args.kwargs
    # Главное в этом тесте — `format=full`. Без него metadata-сервер отдаёт
    # токен без claim `email`, правило федерации перестаёт совпадать, и
    # Anthropic отвечает отказом без внятной причины.
    assert kwargs["params"] == {
        "audience": "https://api.anthropic.com",
        "format": "full",
    }
    assert kwargs["headers"] == {"Metadata-Flavor": "Google"}
    assert kwargs["timeout"] > 0


def test_metadata_failure_propagates():
    """Отказ metadata-сервера обязан оставаться отказом.

    Молча вернуть пустую строку значило бы отправить в Anthropic заведомо
    негодный токен и получить ошибку аутентификации вместо ошибки инфраструктуры.
    """
    with patch("app.core.anthropic_auth.requests.get") as mock_get:
        response = make_metadata_response("")
        response.raise_for_status.side_effect = requests.HTTPError("503")
        mock_get.return_value = response

        with pytest.raises(requests.HTTPError):
            anthropic_auth.fetch_identity_token()


def test_client_authenticates_by_federation():
    from app.services import ai

    assert isinstance(ai.client.credentials, WorkloadIdentityCredentials)
    assert ai.client.api_key is None
    assert ai.client.auth_token is None


def test_stray_api_key_env_is_ignored(monkeypatch):
    """Забытая переменная окружения не должна подменять способ входа.

    SDK читает `ANTHROPIC_API_KEY` только когда учётные данные не переданы
    явно. Проверка закрепляет это поведение: оно неочевидно и держится на
    внутреннем правиле библиотеки, которое может измениться при обновлении.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-stray-value")

    client = anthropic.AsyncAnthropic(
        credentials=anthropic_auth.build_credentials(),
        timeout=30.0,
    )

    assert client.api_key is None
