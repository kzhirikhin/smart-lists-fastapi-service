from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    service_secret: str
    anthropic_api_key: str
    debug: bool = False

    # Проверка вызывающего по Google ID-токену. Оба значения несекретные:
    # email service account и адрес самого сервиса.
    #
    # Optional намеренно: пока они не заданы, работает только shared secret.
    # Это делает переход безопасным в обе стороны — выкатка сервиса не зависит
    # от того, успели ли появиться переменные, а откат не требует их убирать.
    # После шага 3 (сервис перестаёт принимать секрет) они станут обязательными.
    expected_caller_sa: Optional[str] = None
    service_audience: Optional[str] = None

settings = Settings() # type: ignore[call-arg]
