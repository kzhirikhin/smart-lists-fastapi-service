from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    anthropic_api_key: str
    debug: bool = False

    # Проверка вызывающего по Google ID-токену. Оба значения несекретные:
    # email service account и адрес самого сервиса. `SERVICE_AUDIENCE`
    # принимает список через запятую — у сервиса Cloud Run бывает несколько
    # действующих адресов, и токен выпускается под тот, что настроен у
    # вызывающего.
    #
    # Обязательные: shared secret удалён, и других способов аутентификации не
    # осталось. Отсутствие любого из них означает сервис, который не может
    # никого пустить, — падать на старте честнее, чем отвечать 403 на всё.
    expected_caller_sa: str
    service_audience: str

settings = Settings() # type: ignore[call-arg]
