import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# Фейковый ответ который будет возвращать мок вместо Claude
def make_mock_response(text: str):
    mock = MagicMock()
    block = MagicMock()
    block.type = "text"
    block.text = text
    mock.content = [block]
    return mock


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_insights_success():
    with patch("app.services.ai.client.messages.create") as mock_create:
        mock_create.return_value = make_mock_response("Тестовый инсайт от Claude")

        response = client.post(
            "/insights",
            json={
                "title": "Тест",
                "items": ["item1", "item2"],
                "user_message": None
            },
            headers={"Authorization": "Bearer test-secret-123"}
        )

        assert response.status_code == 200
        assert response.json() == {"insight": "Тестовый инсайт от Claude"}
        mock_create.assert_called_once()  # убеждаемся что Claude был вызван ровно один раз


def test_insights_wrong_secret():
    response = client.post(
        "/insights",
        json={
            "title": "Тест",
            "items": ["item1"],
            "user_message": None
        },
        headers={"Authorization": "Bearer wrong-secret"}
    )

    assert response.status_code == 403


def test_insights_missing_auth():
    response = client.post(
        "/insights",
        json={
            "title": "Тест",
            "items": ["item1"],
            "user_message": None
        }
        # заголовок Authorization не передаём вообще
    )

    assert response.status_code == 422  # Pydantic: обязательное поле отсутствует


def test_insights_empty_items():
    with patch("app.services.ai.client.messages.create") as mock_create:
        mock_create.return_value = make_mock_response("Список пуст, анализировать нечего")

        response = client.post(
            "/insights",
            json={
                "title": "Пустой список",
                "items": [],
                "user_message": None
            },
            headers={"Authorization": "Bearer test-secret-123"}
        )

        assert response.status_code == 200