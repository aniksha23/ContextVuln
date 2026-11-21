from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "ContextVuln API"
    app_env: str = "development"
    gemini_api_key: str = ""
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()