import pytest
from unittest.mock import patch

CALLER_SA = "vercel-insights-invoker@example.iam.gserviceaccount.com"
SERVICE_AUDIENCE = "https://insights-api.example.run.app"


@pytest.fixture(autouse=True)
def mock_settings():
    """Настройки, которые видит проверка вызывающего.

    Патчится `caller_auth`, а не роутер: роутер не знает, как устроена
    аутентификация, и лишь спрашивает «пускать ли».
    """
    with patch("app.core.caller_auth.settings") as s:
        s.expected_caller_sa = CALLER_SA
        s.service_audience = SERVICE_AUDIENCE
        yield s


@pytest.fixture(autouse=True)
def accept_caller_token():
    """По умолчанию токен считается подлинным.

    Подделать настоящую подпись Google в тесте нельзя, а проверять саму
    криптографию — работа `google-auth`, а не наша. Поэтому библиотека
    замокана, и в этом состоянии любой непустой `Bearer` проходит: остальные
    тесты описывают контракт и бюджеты, и аутентификация им только мешала бы.

    Тесты про саму аутентификацию берут эту же фикстуру и задают ей нужное
    поведение — подставляют чужой email или заставляют проверку упасть.
    """
    with patch(
        "app.core.caller_auth.google_id_token.verify_oauth2_token",
        return_value={"email": CALLER_SA, "email_verified": True},
    ) as verify:
        yield verify
