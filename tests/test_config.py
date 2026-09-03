"""Настройки не читают посторонний `.env` и не раскрывают его содержимое.

Проверяется поведение, найденное 2026-09-03. Скрипт, запущенный из каталога
соседнего репозитория, импортировал `app.core.config`. Путь `env_file=".env"`
разрешался относительно текущего каталога процесса, поэтому pydantic прочитал
`.env` web-приложения, не нашёл под его ключи полей и перечислил их в тексте
`ValidationError` **вместе со значениями** — то есть напечатал чужие секреты в
лог. Опасна была вторая половина: падение на старте заметно и поправимо,
раскрытие секрета — нет.

Обе половины закрыты, и обе проверяются здесь: путь абсолютный и привязан к
файлу настроек, лишние ключи игнорируются. Отдельно проверено, что
`extra="ignore"` не превратил в тишину отсутствие обязательного значения.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings

# Обязательные поля `Settings`. Значения заведомо нерабочие: тесты не должны
# зависеть ни от настоящей конфигурации, ни от сети.
REQUIRED = {
    "EXPECTED_CALLER_SA": "caller@example.iam.gserviceaccount.com",
    "SERVICE_AUDIENCE": "https://insights-api.example.run.app",
    "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_example",
    "ANTHROPIC_ORGANIZATION_ID": "00000000-0000-0000-0000-000000000000",
    "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_example",
    "ANTHROPIC_WORKSPACE_ID": "wrkspc_example",
}

# Маркер, которого не должно оказаться ни в одном поле и ни в одном сообщении
# об ошибке. Формой повторяет то, что реально утекло: ключи чужого приложения,
# среди них перекрывающий наш `EXPECTED_CALLER_SA`.
SECRET_MARKER = "must-not-be-printed"
FOREIGN_ENV = (
    f"AUTH_SECRET={SECRET_MARKER}\n"
    f"S3_SECRET_ACCESS_KEY={SECRET_MARKER}\n"
    "EXPECTED_CALLER_SA=attacker@example.com\n"
)


@pytest.fixture
def required_env(monkeypatch):
    for name, value in REQUIRED.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def no_required_env(monkeypatch):
    for name in REQUIRED:
        monkeypatch.delenv(name, raising=False)


def test_env_file_path_is_absolute_and_anchored_to_the_repository():
    """Путь задан от файла настроек, а не от каталога запуска.

    Относительный путь означал бы «тот `.env`, что окажется рядом с рабочим
    каталогом», и именно это и произошло.
    """
    env_file = Settings.model_config["env_file"]

    assert isinstance(env_file, Path)
    assert env_file.is_absolute()
    assert env_file == Path(__file__).resolve().parents[1] / ".env"


def test_stray_env_file_in_cwd_is_neither_read_nor_printed(
    tmp_path, monkeypatch, required_env
):
    """Чужой `.env` в текущем каталоге не участвует в конфигурации.

    Утверждения два, и второе важнее: настройки не должны ни взять значения
    оттуда, ни назвать их в сообщении об ошибке, если она всё же случится.
    """
    (tmp_path / ".env").write_text(FOREIGN_ENV, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    try:
        settings = Settings()
    except Exception as exc:  # noqa: BLE001 — проверяется в том числе текст
        assert SECRET_MARKER not in str(exc), (
            "значения постороннего .env попали в текст ошибки"
        )
        pytest.fail(f"посторонний .env уронил настройки: {type(exc).__name__}")

    # Проверенное окружение не перекрыто файлом...
    assert settings.expected_caller_sa == REQUIRED["EXPECTED_CALLER_SA"]
    # ...и его ключи не стали полями.
    assert not hasattr(settings, "auth_secret")
    assert SECRET_MARKER not in settings.model_dump_json()


def test_extra_keys_in_the_configured_env_file_are_ignored(
    tmp_path, no_required_env
):
    """Лишний ключ в самом `.env` сервиса не роняет старт и не печатается.

    Проверяется уже не путь, а `extra="ignore"`: файл берётся тот, что указан
    явно, и в нём заведомо есть посторонний ключ.
    """
    env_file = tmp_path / "service.env"
    env_file.write_text(
        "\n".join(f"{name}={value}" for name, value in REQUIRED.items())
        + f"\nS3_SECRET_ACCESS_KEY={SECRET_MARKER}\n",
        encoding="utf-8",
    )

    settings = Settings(_env_file=env_file)  # type: ignore[call-arg]

    assert settings.expected_caller_sa == REQUIRED["EXPECTED_CALLER_SA"]
    assert not hasattr(settings, "s3_secret_access_key")
    assert SECRET_MARKER not in settings.model_dump_json()


def test_missing_required_variable_still_fails(no_required_env):
    """`extra="ignore"` не должен был сделать молчаливым отсутствие нужного.

    Без этой проверки послабление легко перепутать с общей терпимостью к
    конфигурации: обязательное поле обязано ронять старт, как и прежде.
    """
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]
