from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    service_secret: str
    anthropic_api_key: str

    class Config:
        env_file = ".env"

settings = Settings()