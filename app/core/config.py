from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    debug: bool = False

    # Доступ к Anthropic через workload identity federation. Все четыре
    # значения несекретны: идентификаторы правила, организации, сервисного
    # аккаунта и workspace. Секретов в конфигурации сервиса не осталось —
    # ни одного.
    #
    # Обязательные по той же причине, что и проверка вызывающего: другого
    # способа обратиться к Anthropic нет, и сервис без них умеет только
    # возвращать ошибки.
    anthropic_federation_rule_id: str
    anthropic_organization_id: str
    anthropic_service_account_id: str
    anthropic_workspace_id: str

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

    # Какая модель обслуживает инсайты. Значение — имя из `MODEL_CHOICES` в
    # `app/services/ai.py`, а не идентификатор модели: произвольная строка не
    # должна становиться моделью, иначе опечатка в ревизии уедет в Anthropic
    # именем несуществующей модели, а чужое имя — счётом по чужому прайсу.
    #
    # Необязательная и с умолчанием: невыставленная переменная обязана
    # воспроизводить сегодняшнее поведение ровно. Переменная существует ради
    # сравнения моделей на настоящих списках и уедет вместе с ним.
    insights_model: str = "haiku"

settings = Settings() # type: ignore[call-arg]
