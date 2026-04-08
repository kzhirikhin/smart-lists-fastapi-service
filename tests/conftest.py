import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_settings():
    with patch("app.routers.insights.settings") as s:
        s.service_secret = "test-secret-123"
        yield s
