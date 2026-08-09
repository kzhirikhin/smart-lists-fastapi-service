import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_settings():
    """Настройки, которые видит проверка вызывающего.

    Патчится `caller_auth`, а не роутер: с переходом на ID-токены роутер больше
    не знает о секретах и лишь спрашивает «пускать ли».

    Поля токена по умолчанию пустые — это состояние «федерация не настроена»,
    при котором работает только shared secret. Так остальные тесты продолжают
    описывать прежний путь, а новый включается там, где он и проверяется.
    """
    with patch("app.core.caller_auth.settings") as s:
        s.service_secret = "test-secret-123"
        s.expected_caller_sa = None
        s.service_audience = None
        yield s
